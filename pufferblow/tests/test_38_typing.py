"""Typing indicators: the typing.start command, its unsequenced channel event, and DMs.

Stubs the managers instead of starting the app (see test_31 for why the TestClient
fixture is avoided).
"""

from __future__ import annotations

import asyncio
import datetime
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from pufferblow.api.activitypub.activitypub_manager import ActivityPubManager
from pufferblow.api.commands.dispatcher import ConnectionContext
from pufferblow.api.commands.handlers import build_registry
from pufferblow.api.errors import ApiError
from pufferblow.api.events.publisher import InProcessPublisher
from pufferblow.api.principals.authorizer import Authorizer
from pufferblow.api.principals.principal import Principal
from pufferblow.api.protocol import commands as schema
from pufferblow.api.protocol.events import TYPING_STARTED, DomainEvent


class FakeChannels:
    rows = {
        "general": SimpleNamespace(is_private=False, allowed_users=[]),
        "staff": SimpleNamespace(is_private=True, allowed_users=[]),
    }

    def get_channel(self, channel_id: str):
        return self.rows.get(channel_id)


class FakeUsers:
    def __init__(self, timed_out: set[str] = frozenset()) -> None:
        self.timed_out = timed_out

    def get_active_timeout_until(self, user_id: str):
        return datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc) if user_id in self.timed_out else None


def _typing(*, users=None, dm_peer=None):
    registry = build_registry(
        messages=None,
        authorizer=Authorizer(user_manager=users or FakeUsers(), channels_manager=FakeChannels()),
        publisher=None,
        dm_peer=dm_peer,
    )
    return registry["typing.start"].handler


def _ctx(user_id: str = "ada", *privileges: str, kind: str = "user") -> ConnectionContext:
    principal = Principal(id=user_id, kind=kind, privileges=frozenset(privileges or {"send_messages"}))
    return ConnectionContext(principal=principal, session_id="s", connection_key="k")


def _run(handler, ctx, **data):
    return asyncio.run(handler(ctx, schema.TypingStart(**data)))


# ── schema ───────────────────────────────────────────────────────


@pytest.mark.parametrize("data", [{}, {"channel_id": "c", "conversation_id": "d"}])
def test_typing_needs_exactly_one_target(data):
    with pytest.raises(ValidationError):
        schema.TypingStart(**data)


# ── channels ─────────────────────────────────────────────────────


def test_typing_in_a_channel_publishes_an_unsequenced_event():
    output = _run(_typing(), _ctx(), channel_id="general")

    assert output.result == {"delivered": True}
    (event,) = output.events
    assert event.name == TYPING_STARTED
    assert event.channel_id == "general"
    assert event.sequenced is False
    assert event.data["user_id"] == "ada"
    assert event.data["expires_in_ms"] > 0


def test_typing_needs_permission_to_send_there():
    with pytest.raises(ApiError):
        _run(_typing(), _ctx("ada", "read_messages"), channel_id="general")
    with pytest.raises(ApiError):
        _run(_typing(), _ctx(), channel_id="staff")  # private, not a member
    with pytest.raises(ApiError):
        _run(_typing(users=FakeUsers(timed_out={"ada"})), _ctx(), channel_id="general")


def test_an_unsequenced_event_does_not_advance_the_channel_sequence():
    delivered = []

    class Connections:
        async def deliver_channel_event(self, channel_id, frame):
            delivered.append(frame)

    publisher = InProcessPublisher(Connections())
    event = DomainEvent(name=TYPING_STARTED, data={}, channel_id="general", sequenced=False)
    asyncio.run(publisher.publish(event))

    assert publisher.current_seq("general") == 0
    assert "seq" not in delivered[0]
    assert delivered[0]["channel_id"] == "general"


# ── direct messages ──────────────────────────────────────────────


def test_typing_in_a_dm_goes_only_to_the_peer():
    output = _run(_typing(dm_peer=lambda conversation, user: "bob"), _ctx(), conversation_id="dm-1")

    assert output.result == {"delivered": True}
    (event,) = output.events
    assert event.target_user_id == "bob"
    assert event.channel_id is None
    assert event.data["conversation_id"] == "dm-1"


def test_typing_in_a_dm_you_are_not_in_is_quietly_dropped():
    output = _run(_typing(dm_peer=lambda conversation, user: None), _ctx(), conversation_id="dm-1")
    assert output.result == {"delivered": False}
    assert output.events == []


def test_bots_do_not_type_in_dms():
    output = _run(_typing(dm_peer=lambda conversation, user: "bob"), _ctx("bot", kind="bot"), conversation_id="dm-1")
    assert output.events == []


class FakeDatabase:
    def __init__(self, other_sender: str | None, actors: dict) -> None:
        self.other_sender = other_sender
        self.actors = actors

    def get_conversation_other_sender(self, conversation_id: str, viewer_user_id: str):
        return self.other_sender

    def get_activitypub_actor_by_user_id(self, user_id: str):
        return self.actors.get(user_id)


ACTORS = {
    "ada": SimpleNamespace(actor_uri="https://x/users/ada", is_local=True),
    "bob": SimpleNamespace(actor_uri="https://x/users/bob", is_local=True),
    "eve": SimpleNamespace(actor_uri="https://x/users/eve", is_local=True),
}
ADA_BOB = ActivityPubManager._conversation_id("https://x/users/ada", "https://x/users/bob")


def _local_dm_peer(database, conversation_id: str, viewer: str):
    manager = SimpleNamespace(database_handler=database, _conversation_id=ActivityPubManager._conversation_id)
    return ActivityPubManager.local_dm_peer(manager, conversation_id, viewer)


def test_local_dm_peer_finds_the_other_participant():
    assert _local_dm_peer(FakeDatabase("bob", ACTORS), ADA_BOB, "ada") == "bob"


def test_local_dm_peer_refuses_someone_outside_the_conversation():
    # Eve knows the conversation id; the other sender query happily returns a participant.
    assert _local_dm_peer(FakeDatabase("bob", ACTORS), ADA_BOB, "eve") is None


def test_local_dm_peer_skips_remote_and_unanswered_conversations():
    remote = {**ACTORS, "bob": SimpleNamespace(actor_uri="https://x/users/bob", is_local=False)}
    assert _local_dm_peer(FakeDatabase("bob", remote), ADA_BOB, "ada") is None
    assert _local_dm_peer(FakeDatabase(None, ACTORS), ADA_BOB, "ada") is None
