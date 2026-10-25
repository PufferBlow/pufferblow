"""A DM call leaves a line in the conversation: how it ended, and how long it lasted if it was picked up."""

from __future__ import annotations

import datetime
import types
import uuid

import pytest
from fastapi.testclient import TestClient

from pufferblow.api.voice.dm_call_manager import DmCallManager
from pufferblow.core.bootstrap import api_initializer

CALLS = "/api/v1/dm-calls"


@pytest.fixture(autouse=True)
def _activitypub_tables(client):
    import pufferblow.api.database.tables.activitypub  # noqa: F401
    from pufferblow.api.database.tables.declarative_base import Base

    Base.metadata.create_all(
        api_initializer.database_handler.database_engine,
        tables=[t for t in Base.metadata.sorted_tables if t.name.startswith("activitypub")],
    )


def _user(name: str):
    user = api_initializer.user_manager.sign_up(username=f"{name}_{uuid.uuid4().hex[:5]}", password="12345678")
    token = api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user.user_id), origin_server=user.origin_server)["access_token"]
    return str(user.user_id), user.username, token


def _ring(client: TestClient, caller_token: str, callee_id: str) -> str:
    reply = client.post(f"{CALLS}/{callee_id}/invite", json={"auth_token": caller_token, "callee_id": callee_id})
    assert reply.status_code == 200, reply.text
    return reply.json()["call_id"]


def _act(client: TestClient, action: str, call_id: str, token: str):
    return client.post(f"{CALLS}/{call_id}/{action}", json={"auth_token": token})


def _calls_in_chat(client: TestClient, token: str, peer: str, headers: dict | None = None) -> list[dict]:
    loaded = client.get("/api/v1/dms/messages", params={"auth_token": token, "peer": peer, "page": 1, "messages_per_page": 50}, headers=headers)
    assert loaded.status_code == 200, loaded.text
    return [a["call"] for m in loaded.json()["messages"] for a in m.get("attachments", []) if a.get("type") == "call"]


def test_a_call_that_was_picked_up_keeps_how_long_it_lasted(client: TestClient):
    alice_id, alice_name, alice = _user("alice")
    bob_id, bob_name, bob = _user("bob")
    call_id = _ring(client, alice, bob_id)
    assert _act(client, "accept", call_id, bob).status_code == 200
    api_initializer.dm_call_manager._calls[call_id]["accepted_at"] -= datetime.timedelta(minutes=4, seconds=30)

    assert _act(client, "end", call_id, alice).status_code == 200

    for token, peer in ((alice, bob_name), (bob, alice_name)):
        [log] = _calls_in_chat(client, token, peer)
        assert (log["outcome"], log["caller_id"], log["callee_id"]) == ("completed", alice_id, bob_id)
        assert 269 <= log["duration_seconds"] <= 275


def test_a_declined_call_is_kept(client: TestClient):
    alice_id, _, alice = _user("alice")
    bob_id, bob_name, bob = _user("bob")
    call_id = _ring(client, alice, bob_id)

    assert _act(client, "reject", call_id, bob).status_code == 200

    [log] = _calls_in_chat(client, alice, bob_name)
    assert (log["outcome"], log["caller_id"], log["duration_seconds"]) == ("declined", alice_id, 0)


def test_a_call_the_caller_hung_up_before_it_was_answered_is_kept_as_cancelled(client: TestClient):
    _, alice_name, alice = _user("alice")
    bob_id, _, bob = _user("bob")
    call_id = _ring(client, alice, bob_id)

    assert _act(client, "reject", call_id, alice).status_code == 200  # the caller giving up

    [log] = _calls_in_chat(client, bob, alice_name)
    assert log["outcome"] == "cancelled"


def test_a_call_nobody_answered_is_kept_as_missed_even_if_only_noticed_later(client: TestClient):
    alice_id, alice_name, alice = _user("alice")
    bob_id, bob_name, bob = _user("bob")
    call_id = _ring(client, alice, bob_id)
    api_initializer.dm_call_manager._calls[call_id]["created_at"] -= datetime.timedelta(minutes=2)  # it rang out

    # The caller's app then hangs up on its own; the call is already gone, but its line is not lost.
    assert _act(client, "end", call_id, alice).status_code == 400

    [log] = _calls_in_chat(client, bob, alice_name)
    assert log["outcome"] == "missed"
    assert [c["outcome"] for c in _calls_in_chat(client, alice, bob_name)] == ["missed"]


def test_a_call_is_logged_once_however_many_requests_notice_it(client: TestClient):
    alice_id, alice_name, alice = _user("alice")
    bob_id, bob_name, bob = _user("bob")
    call_id = _ring(client, alice, bob_id)
    assert _act(client, "reject", call_id, bob).status_code == 200
    assert _act(client, "reject", call_id, bob).status_code == 400
    assert _act(client, "end", call_id, alice).status_code == 400
    assert len(_calls_in_chat(client, alice, bob_name)) == 1


def test_a_log_line_is_delivered_live_to_both_people(client: TestClient):
    alice_id, alice_name, alice = _user("alice")
    bob_id, bob_name, bob = _user("bob")
    call_id = _ring(client, alice, bob_id)

    with client.websocket_connect(f"/ws?auth_token={bob}&protocol=1") as bob_ws:
        bob_ws.receive_json()
        assert _act(client, "reject", call_id, bob).status_code == 200
        for _ in range(20):
            frame = bob_ws.receive_json()
            if frame.get("name") == "dm.message.created":
                data = frame["data"]
                break
        else:
            raise AssertionError("the log line was not delivered")
    assert data["attachments"][0]["type"] == "call" and data["attachments"][0]["call"]["outcome"] == "declined"
    assert data["sender_user_id"] == alice_id


def test_a_call_ended_because_someone_went_offline_is_kept_too(client: TestClient):
    import asyncio

    _, alice_name, alice = _user("alice")
    bob_id, bob_name, bob = _user("bob")
    call_id = _ring(client, alice, bob_id)
    assert _act(client, "accept", call_id, bob).status_code == 200
    api_initializer.dm_call_manager._calls[call_id]["accepted_at"] -= datetime.timedelta(seconds=90)

    asyncio.run(api_initializer.websockets_manager._end_calls_if_offline(bob_id))  # bob has no connection left

    [log] = _calls_in_chat(client, alice, bob_name)
    assert log["outcome"] == "completed" and 85 <= log["duration_seconds"] <= 95


def test_the_conversation_list_words_a_call_line_and_the_line_names_both_people(client: TestClient):
    _, alice_name, alice = _user("alice")
    bob_id, bob_name, bob = _user("bob")
    call_id = _ring(client, alice, bob_id)
    assert _act(client, "accept", call_id, bob).status_code == 200
    api_initializer.dm_call_manager._calls[call_id]["accepted_at"] -= datetime.timedelta(hours=1, minutes=12)
    assert _act(client, "end", call_id, bob).status_code == 200

    listed = client.get("/api/v1/dms/conversations", params={"auth_token": bob}).json()["conversations"]
    assert [c["last_message_preview"] for c in listed] == ["Voice call · 1 hr 12 min"]
    [log] = _calls_in_chat(client, bob, alice_name)
    assert (log["caller_name"], log["callee_name"]) == (alice_name, bob_name)


def test_a_hostile_host_header_cannot_steer_any_actor_or_call_line(client: TestClient):
    """Identities and lines are built on the instance's own address, whatever Host a request carried."""
    alice_id, alice_name, alice = _user("alice")
    bob_id, bob_name, bob = _user("bob")
    hostile = {"host": "evil.example"}
    call_id = client.post(f"{CALLS}/{bob_id}/invite", json={"auth_token": alice, "callee_id": bob_id}, headers=hostile).json()["call_id"]
    assert client.post(f"{CALLS}/{call_id}/reject", json={"auth_token": bob}, headers=hostile).status_code == 200

    db = api_initializer.database_handler
    uris = [db.get_activitypub_actor_by_user_id(user_id=u).actor_uri for u in (alice_id, bob_id)]
    assert not any("evil.example" in uri for uri in uris)
    assert all(uri.startswith(api_initializer.activitypub_manager.canonical_base_url()) for uri in uris)
    assert len(_calls_in_chat(client, alice, bob_name, headers=hostile)) == 1  # and reading it back does not depend on the Host either


def test_an_existing_actor_keeps_its_address_and_its_conversations_when_the_host_differs(client: TestClient):
    """Conversation ids come from the actors on record, so a request from another address still finds them."""
    alice_id, alice_name, alice = _user("alice")
    bob_id, bob_name, bob = _user("bob")
    sent = client.post("/api/v1/dms/send", json={"auth_token": alice, "peer": bob_name, "message": "hello", "attachments": []})
    assert sent.status_code == 201, sent.text
    listed = client.get("/api/v1/dms/conversations", params={"auth_token": bob}, headers={"host": "other-name.example"}).json()["conversations"]
    assert [c["last_message_preview"] for c in listed] == ["hello"]


def test_the_canonical_address_comes_from_the_instance_not_a_request():
    manager = api_initializer.activitypub_manager
    real = manager.database_handler.get_server

    def server_with(server_id):
        return lambda: types.SimpleNamespace(server_id=server_id)

    try:
        manager.database_handler.get_server = server_with("chat.example.com")
        assert manager.canonical_base_url() == "https://chat.example.com"
        manager.database_handler.get_server = server_with("localhost:7575")
        assert manager.canonical_base_url() == "http://localhost:7575"
        manager.database_handler.get_server = server_with("chat.example.com:8443")
        assert manager.canonical_base_url() == "https://chat.example.com:8443"
        for odd in ("", None, "evil.example/path", "a b", "x@y"):
            manager.database_handler.get_server = server_with(odd)
            assert manager.canonical_base_url() == manager.build_base_url()  # falls back to the configured address
    finally:
        manager.database_handler.get_server = real


# ── how the manager decides the outcome ───────────────────────────


def _manager(ring_timeout_seconds: int = 45) -> DmCallManager:
    friends = types.SimpleNamespace(is_viewer_blocked_by=lambda **_: False)
    return DmCallManager(friends_manager=friends, voice_session_manager=types.SimpleNamespace(), ring_timeout_seconds=ring_timeout_seconds)


def test_the_manager_names_each_way_a_call_can_end():
    manager = _manager()

    def outcome_of(start) -> dict:
        call = manager.invite(caller_id="a", callee_id="b")
        start(call["call_id"])
        [finished] = manager.drain_finished()
        assert finished["call_id"] == call["call_id"]
        return finished

    assert outcome_of(lambda c: manager.reject(call_id=c, user_id="a"))["outcome"] == "cancelled"
    manager._recent.clear()
    assert outcome_of(lambda c: manager.reject(call_id=c, user_id="b"))["outcome"] == "declined"
    manager._recent.clear()
    assert outcome_of(lambda c: manager.end(call_id=c, user_id="a"))["outcome"] == "cancelled"
    manager._recent.clear()
    assert outcome_of(lambda c: manager.end_all_for_user("b"))["outcome"] == "declined"  # the callee's connection went away
    manager._recent.clear()

    def answered_then_over(call_id: str) -> None:
        manager.accept(call_id=call_id, user_id="b")
        manager._calls[call_id]["accepted_at"] -= datetime.timedelta(hours=1, minutes=2, seconds=3)
        manager.end(call_id=call_id, user_id="b")

    done = outcome_of(answered_then_over)
    assert done["outcome"] == "completed" and 3722 <= done["duration_seconds"] <= 3730
    assert manager.drain_finished() == []  # each is handed over once


def test_a_ringing_call_that_times_out_is_missed():
    manager = _manager(ring_timeout_seconds=0)
    call = manager.invite(caller_id="a", callee_id="b")
    import time

    time.sleep(0.01)
    assert [c["call_id"] for c in manager.sweep_expired()] == [call["call_id"]]
    [finished] = manager.drain_finished()
    assert (finished["outcome"], finished["duration_seconds"]) == ("missed", 0)
