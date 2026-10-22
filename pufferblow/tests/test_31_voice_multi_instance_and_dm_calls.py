"""Multi-instance SFU registry/routing and 1:1 DM call signaling.

Deliberately does NOT use the `client`/`TestClient` fixture from conftest —
that fixture calls `api_initializer.load_objects()`, which constructs a
`StorageManager`, which on some environments (python-magic's native
`libmagic` binding) can crash the interpreter outright. Nothing under test
here touches storage, so these tests build only the pieces they need
(`DatabaseHandler`, `VoiceSessionManager`, `DmCallManager`, `FriendsManager`)
directly against a throwaway SQLite file, the same way
`test_28_activitypub_signatures_and_collections.py` avoids the full
bootstrap for activitypub-manager-only tests.
"""

from __future__ import annotations

import datetime
import os
import tempfile
import uuid

import pytest
import sqlalchemy
from sqlalchemy import select

from pufferblow.api.auth.auth_token_manager import AuthTokenManager
from pufferblow.api.channels.channels_manager import ChannelsManager
from pufferblow.api.database.database_handler import DatabaseHandler
from pufferblow.api.database.tables.friend_request_blocks import FriendRequestBlocks
from pufferblow.api.database.tables.media_sfu_instances import MediaSFUInstance
from pufferblow.api.database.tables.voice_sessions import VoiceSession
from pufferblow.api.encrypt.encrypt import Encrypt
from pufferblow.api.friends.friends_manager import FriendsManager
from pufferblow.api.models.config_model import Config
from pufferblow.api.voice.dm_call_manager import MAX_SIGNAL_BYTES, CallBusy, DmCallManager
from pufferblow.api.voice.voice_session_manager import VoiceSessionManager
from pufferblow.api.websocket.websocket_manager import WebSocketsManager


@pytest.fixture
def db():
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp.close()
    engine = sqlalchemy.create_engine(f"sqlite:///{tmp.name}")
    handler = DatabaseHandler(
        database_engine=engine, encrypt_manager=Encrypt(), config=Config()
    )
    yield handler
    # Windows keeps the sqlite file handle open via the connection pool
    # until the engine is disposed; unlinking first (as the `client`
    # fixture in conftest.py does) races that and intermittently raises
    # PermissionError here. Dispose first, and tolerate failure either way
    # since this is OS temp-file cleanup, not part of what's under test.
    handler.database_engine.dispose()
    try:
        if os.path.exists(tmp.name):
            os.unlink(tmp.name)
    except PermissionError:
        pass


@pytest.fixture
def vsm(db):
    auth_manager = AuthTokenManager(database_handler=db, encrypt_manager=db.encrypt_manager)
    channels_manager = ChannelsManager(
        database_handler=db, auth_token_manager=auth_manager, encrypt_manager=db.encrypt_manager
    )
    return VoiceSessionManager(
        database_handler=db,
        auth_token_manager=auth_manager,
        channels_manager=channels_manager,
        websockets_manager=WebSocketsManager(user_manager=None),
    )


@pytest.fixture
def dm_calls(db, vsm):
    friends_manager = FriendsManager(database_handler=db)
    return DmCallManager(friends_manager=friends_manager, voice_session_manager=vsm)


def _register(vsm, instance_id, region, signaling_url, current_peers, max_total_peers=100):
    vsm.record_instance_heartbeat(
        instance_id=instance_id,
        region=region,
        signaling_url=signaling_url,
        internal_api_base=None,
        current_peers=current_peers,
        max_total_peers=max_total_peers,
    )


def _new_user_id() -> str:
    return str(uuid.uuid4())


# ── Instance registry + routing ──────────────────────────────────────────


def test_heartbeat_upserts_instance_row(db, vsm):
    _register(vsm, "sfu-a", "eu-west", "wss://sfu-a.example.com/rtc/v1/ws", current_peers=50)

    with db.database_session() as session:
        row = session.get(MediaSFUInstance, "sfu-a")
        assert row is not None
        assert row.region == "eu-west"
        assert row.current_peers == 50
        assert row.status == "active"


def test_select_sfu_instance_picks_least_loaded(db, vsm):
    _register(vsm, "sfu-a", "eu-west", "wss://sfu-a.example.com/rtc/v1/ws", current_peers=50)
    _register(vsm, "sfu-b", "eu-west", "wss://sfu-b.example.com/rtc/v1/ws", current_peers=10)
    _register(vsm, "sfu-c", "us-east", "wss://sfu-c.example.com/rtc/v1/ws", current_peers=0)

    with db.database_session() as session:
        chosen = vsm._select_sfu_instance(session, region_hint=None)
        session.commit()
    assert chosen.instance_id == "sfu-c"


def test_select_sfu_instance_prefers_region_hint(db, vsm):
    _register(vsm, "sfu-a", "eu-west", "wss://sfu-a.example.com/rtc/v1/ws", current_peers=50)
    _register(vsm, "sfu-b", "eu-west", "wss://sfu-b.example.com/rtc/v1/ws", current_peers=10)
    _register(vsm, "sfu-c", "us-east", "wss://sfu-c.example.com/rtc/v1/ws", current_peers=0)

    with db.database_session() as session:
        chosen = vsm._select_sfu_instance(session, region_hint="eu-west")
        session.commit()
    # sfu-c is globally least loaded but out of region; within eu-west, sfu-b wins.
    assert chosen.instance_id == "sfu-b"


def test_stale_heartbeat_marks_instance_dead_and_excludes_it(db, vsm):
    _register(vsm, "sfu-a", "eu-west", "wss://sfu-a.example.com/rtc/v1/ws", current_peers=50)
    _register(vsm, "sfu-c", "us-east", "wss://sfu-c.example.com/rtc/v1/ws", current_peers=0)

    with db.database_session() as session:
        row = session.get(MediaSFUInstance, "sfu-c")
        row.last_heartbeat_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
            seconds=120
        )
        session.commit()

    with db.database_session() as session:
        chosen = vsm._select_sfu_instance(session, region_hint=None)
        session.commit()
    assert chosen.instance_id == "sfu-a"

    with db.database_session() as session:
        row = session.get(MediaSFUInstance, "sfu-c")
        assert row.status == "dead"


def test_dm_fallback_session_uses_instance_selection_and_is_shared(db, vsm):
    _register(vsm, "sfu-a", "default", "wss://sfu-a.example.com/rtc/v1/ws", current_peers=50)
    _register(vsm, "sfu-b", "default", "wss://sfu-b.example.com/rtc/v1/ws", current_peers=10)

    user1, user2 = _new_user_id(), _new_user_id()
    result1 = vsm.create_or_join_dm_fallback_session(user_id=user1, call_id="call-xyz")
    assert "sfu-b.example.com" in result1["signaling_url"]
    assert result1["backend"] == "sfu_v2_dm_fallback"

    result2 = vsm.create_or_join_dm_fallback_session(user_id=user2, call_id="call-xyz")
    assert result2["session_id"] == result1["session_id"]

    with db.database_session() as session:
        vs = session.execute(
            select(VoiceSession).where(VoiceSession.channel_id == "call-xyz")
        ).scalar_one()
        assert vs.sfu_instance_id == "sfu-b"


def test_dm_fallback_session_migrates_off_a_draining_instance(db, vsm):
    _register(vsm, "sfu-a", "default", "wss://sfu-a.example.com/rtc/v1/ws", current_peers=50)
    _register(vsm, "sfu-b", "default", "wss://sfu-b.example.com/rtc/v1/ws", current_peers=10)

    user1 = _new_user_id()
    first = vsm.create_or_join_dm_fallback_session(user_id=user1, call_id="call-xyz")
    assert "sfu-b.example.com" in first["signaling_url"]

    with db.database_session() as session:
        row = session.get(MediaSFUInstance, "sfu-b")
        row.status = "draining"
        session.commit()

    second = vsm.create_or_join_dm_fallback_session(user_id=user1, call_id="call-xyz")
    assert "sfu-a.example.com" in second["signaling_url"]


# ── DM call signaling ─────────────────────────────────────────────────────


def test_invite_accept_signal_end_flow(dm_calls):
    alice, bob = _new_user_id(), _new_user_id()

    call = dm_calls.invite(caller_id=alice, callee_id=bob)
    assert call["status"] == "ringing"

    accepted = dm_calls.accept(call_id=call["call_id"], user_id=bob)
    assert accepted["status"] == "accepted"

    with pytest.raises(ValueError):
        dm_calls.accept(call_id=call["call_id"], user_id=alice)

    relayed = dm_calls.relay_signal(
        call_id=call["call_id"], user_id=alice, signal_type="offer", payload={"sdp": "..."}
    )
    assert relayed["to_user_id"] == bob
    assert relayed["from_user_id"] == alice

    ended = dm_calls.end(call_id=call["call_id"], user_id=bob)
    assert ended["other_user_id"] == alice

    with pytest.raises(ValueError):
        dm_calls.relay_signal(
            call_id=call["call_id"], user_id=alice, signal_type="candidate", payload={}
        )


def test_invite_rejects_self_call(dm_calls):
    alice = _new_user_id()
    with pytest.raises(ValueError):
        dm_calls.invite(caller_id=alice, callee_id=alice)


def test_reject_notifies_caller_and_clears_call(dm_calls):
    alice, bob = _new_user_id(), _new_user_id()
    call = dm_calls.invite(caller_id=alice, callee_id=bob)

    rejected = dm_calls.reject(call_id=call["call_id"], user_id=bob)
    assert rejected["other_user_id"] == alice

    with pytest.raises(ValueError):
        dm_calls.accept(call_id=call["call_id"], user_id=bob)


def test_blocked_callee_rejects_invite(db, dm_calls):
    carol, dave = _new_user_id(), _new_user_id()
    with db.database_session() as session:
        session.add(FriendRequestBlocks(blocker_id=carol, blocked_id=dave))
        session.commit()

    with pytest.raises(ValueError):
        dm_calls.invite(caller_id=dave, callee_id=carol)

    # The reverse direction (blocker calling the person they blocked) is
    # also refused — `invite` checks both directions.
    with pytest.raises(ValueError):
        dm_calls.invite(caller_id=carol, callee_id=dave)


def test_dm_call_sfu_fallback_requires_participant(dm_calls):
    alice, bob, eve = _new_user_id(), _new_user_id(), _new_user_id()
    call = dm_calls.invite(caller_id=alice, callee_id=bob)
    dm_calls.accept(call_id=call["call_id"], user_id=bob)

    with pytest.raises(ValueError):
        dm_calls.request_sfu_fallback(call_id=call["call_id"], user_id=eve)

    payload = dm_calls.request_sfu_fallback(call_id=call["call_id"], user_id=alice)
    assert payload["backend"] == "sfu_v2_dm_fallback"


# ── ringing out, busy lines, dropped connections, signal size ────────────


def _backdate(dm_calls, call_id, seconds):
    dm_calls._calls[call_id]["created_at"] -= datetime.timedelta(seconds=seconds)


def test_a_call_nobody_answers_is_dropped_after_the_ring_timeout(dm_calls):
    alice, bob = _new_user_id(), _new_user_id()
    call = dm_calls.invite(caller_id=alice, callee_id=bob)
    _backdate(dm_calls, call["call_id"], dm_calls.ring_timeout_seconds + 1)

    dropped = dm_calls.sweep_expired()

    assert [c["call_id"] for c in dropped] == [call["call_id"]]
    with pytest.raises(ValueError):
        dm_calls.accept(call_id=call["call_id"], user_id=bob)  # too late to pick up
    assert dm_calls.invite(caller_id=alice, callee_id=bob)["status"] == "ringing"  # and the line is free again


def test_an_answered_call_does_not_time_out(dm_calls):
    alice, bob = _new_user_id(), _new_user_id()
    call = dm_calls.invite(caller_id=alice, callee_id=bob)
    dm_calls.accept(call_id=call["call_id"], user_id=bob)
    _backdate(dm_calls, call["call_id"], 10_000)
    assert dm_calls.sweep_expired() == []


def test_someone_on_a_call_cannot_be_rung_or_ring_out(dm_calls):
    alice, bob, carol = _new_user_id(), _new_user_id(), _new_user_id()
    dm_calls.invite(caller_id=alice, callee_id=bob)

    with pytest.raises(CallBusy):
        dm_calls.invite(caller_id=carol, callee_id=bob)  # bob is being rung
    with pytest.raises(CallBusy):
        dm_calls.invite(caller_id=alice, callee_id=carol)  # alice is already calling

    # Both busy refusals read the same, so the caller learns nothing about who is on a call.
    with pytest.raises(CallBusy, match="Cannot call this user right now"):
        dm_calls.invite(caller_id=carol, callee_id=alice)


def test_ending_a_call_frees_both_lines(dm_calls):
    alice, bob, carol = _new_user_id(), _new_user_id(), _new_user_id()
    call = dm_calls.invite(caller_id=alice, callee_id=bob)
    dm_calls.accept(call_id=call["call_id"], user_id=bob)
    dm_calls.end(call_id=call["call_id"], user_id=alice)

    assert dm_calls.invite(caller_id=carol, callee_id=bob)["status"] == "ringing"


def test_a_dropped_connection_ends_the_calls_that_person_was_in(dm_calls):
    alice, bob = _new_user_id(), _new_user_id()
    call = dm_calls.invite(caller_id=alice, callee_id=bob)
    dm_calls.accept(call_id=call["call_id"], user_id=bob)

    ended = dm_calls.end_all_for_user(bob)

    assert [(c["call_id"], c["other_user_id"]) for c in ended] == [(call["call_id"], alice)]
    with pytest.raises(ValueError):
        dm_calls.relay_signal(call_id=call["call_id"], user_id=alice, signal_type="candidate", payload={})
    assert dm_calls.end_all_for_user(bob) == []


def test_an_oversized_signal_is_refused_not_relayed(dm_calls):
    alice, bob = _new_user_id(), _new_user_id()
    call = dm_calls.invite(caller_id=alice, callee_id=bob)
    dm_calls.accept(call_id=call["call_id"], user_id=bob)

    with pytest.raises(ValueError, match="too large"):
        dm_calls.relay_signal(call_id=call["call_id"], user_id=alice, signal_type="offer", payload={"sdp": "x" * (MAX_SIGNAL_BYTES + 1)})
    assert dm_calls.relay_signal(call_id=call["call_id"], user_id=alice, signal_type="relay", payload={"relay_key": {"v": 1}})["to_user_id"] == bob


class _FakeSocket:
    def __init__(self):
        self.sent = []

    async def send_json(self, frame):
        self.sent.append(frame)


def test_a_dropped_connection_tells_the_other_side_the_call_ended(dm_calls):
    import asyncio

    alice, bob = _new_user_id(), _new_user_id()
    call = dm_calls.invite(caller_id=alice, callee_id=bob)
    dm_calls.accept(call_id=call["call_id"], user_id=bob)

    manager = WebSocketsManager(user_manager=None)
    manager.dm_call_manager = dm_calls
    alices_socket = _FakeSocket()
    manager.active_connections[alices_socket] = {"user_id": alice}

    asyncio.run(manager._end_calls_if_offline(bob))  # bob has no connection left

    frames = [f for f in alices_socket.sent if f.get("name") == "user.dm_call_ended"]
    assert [f["data"] for f in frames] == [{"call_id": call["call_id"]}]
    with pytest.raises(ValueError):
        dm_calls.accept(call_id=call["call_id"], user_id=bob)


def test_a_person_with_another_open_connection_keeps_their_call(dm_calls):
    import asyncio

    alice, bob = _new_user_id(), _new_user_id()
    call = dm_calls.invite(caller_id=alice, callee_id=bob)
    manager = WebSocketsManager(user_manager=None)
    manager.dm_call_manager = dm_calls
    manager.active_connections[_FakeSocket()] = {"user_id": bob}  # a second tab

    asyncio.run(manager._end_calls_if_offline(bob))

    assert dm_calls.accept(call_id=call["call_id"], user_id=bob)["status"] == "accepted"
