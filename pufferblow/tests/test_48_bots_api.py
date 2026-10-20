"""Bots: the owner-only API to create and revoke them, and what a bot can and cannot do with its scopes.

The first half goes through the HTTP routes; the second opens real protocol sockets with a bot's token.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import WebSocketDisconnect
from fastapi.testclient import TestClient

from pufferblow.core.bootstrap import api_initializer

BOTS = "/api/v1/bots"


def _user(name: str, *, owner: bool = False):
    user = api_initializer.user_manager.sign_up(username=f"{name}_{uuid.uuid4().hex[:6]}", password="12345678", is_owner=owner)
    token = api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user.user_id), origin_server=user.origin_server)["access_token"]
    return user, token


def _create(client: TestClient, owner_token: str, name: str = "helper", scopes=None):
    response = client.post(BOTS, json={"auth_token": owner_token, "name": name, "scopes": scopes if scopes is not None else ["send_messages"]})
    assert response.status_code == 201, response.text
    return response.json()


def _channel(owner_user, *, private: bool = False) -> str:
    return str(
        api_initializer.channels_manager.create_channel(
            user_id=str(owner_user.user_id), channel_name=f"c_{uuid.uuid4().hex[:8]}", is_private=private, channel_type="text"
        ).channel_id
    )


# ── the API ───────────────────────────────────────────────────────


def test_the_owner_creates_a_bot_and_gets_its_token_once(client: TestClient):
    _, owner_token = _user("owner", owner=True)

    created = _create(client, owner_token, "greeter", ["send_messages"])

    assert created["token"].startswith("pbb_")
    assert created["bot"]["name"] == "greeter" and created["bot"]["scopes"] == ["send_messages"]
    # Only a hash is stored; the token resolves, and is not in the listing.
    assert api_initializer.bot_manager.verify_token(created["token"]) is not None
    listing = client.get(BOTS, params={"auth_token": owner_token})
    assert listing.status_code == 200
    assert created["token"] not in listing.text and "token_hash" not in listing.text
    [entry] = listing.json()["bots"]
    assert entry["bot_id"] == created["bot"]["bot_id"] and entry["revoked"] is False and entry["enabled"] is True


def test_only_the_owner_may_manage_bots(client: TestClient):
    _, owner_token = _user("owner", owner=True)
    _, member_token = _user("member")
    created = _create(client, owner_token)

    assert client.post(BOTS, json={"auth_token": member_token, "name": "mine"}).status_code == 403
    assert client.get(BOTS, params={"auth_token": member_token}).status_code == 403
    assert client.delete(f"{BOTS}/{created['bot']['bot_id']}", params={"auth_token": member_token}).status_code == 403
    assert client.post(BOTS, json={"auth_token": "abcd", "name": "x"}).status_code == 401
    assert api_initializer.bot_manager.verify_token(created["token"]) is not None  # the refused delete changed nothing


@pytest.mark.parametrize("scopes", [["administrator"], ["manage_roles"], ["send_messages", "delete_messages"], ["*"]])
def test_a_bot_cannot_be_given_administrative_scopes(client: TestClient, scopes):
    _, owner_token = _user("owner", owner=True)

    response = client.post(BOTS, json={"auth_token": owner_token, "name": "greedy", "scopes": scopes})

    assert response.status_code == 400
    assert response.json()["details"]["allowed_scopes"] == ["send_messages", "view_private_channels"]
    assert client.get(BOTS, params={"auth_token": owner_token}).json()["bots"] == []


def test_revoking_a_bot_stops_its_token_at_once(client: TestClient):
    _, owner_token = _user("owner", owner=True)
    created = _create(client, owner_token)
    bot_id = created["bot"]["bot_id"]

    first = client.delete(f"{BOTS}/{bot_id}", params={"auth_token": owner_token})
    second = client.delete(f"{BOTS}/{bot_id}", params={"auth_token": owner_token})

    assert first.status_code == 200 and first.json()["revoked"] is True
    assert second.status_code == 200 and second.json()["revoked"] is False  # idempotent
    assert api_initializer.bot_manager.verify_token(created["token"]) is None
    [entry] = client.get(BOTS, params={"auth_token": owner_token}).json()["bots"]
    assert entry["revoked"] is True and entry["enabled"] is False
    assert client.delete(f"{BOTS}/nope", params={"auth_token": owner_token}).status_code == 404


def test_a_bot_token_is_not_a_login_for_the_rest_of_the_api(client: TestClient):
    _, owner_token = _user("owner", owner=True)
    token = _create(client, owner_token)["token"]

    assert client.post("/api/v1/users/profile", json={"auth_token": token}).status_code == 401
    assert client.get(BOTS, params={"auth_token": token}).status_code in (400, 401, 403)  # a bot cannot mint bots


# ── scopes, over real sockets ─────────────────────────────────────


def _command(name: str, data: dict, command_id: str = "cmd_1") -> dict:
    return {"type": "command", "version": 1, "id": command_id, "name": name, "data": data}


def _send(ws, name: str, data: dict) -> dict:
    ws.send_json(_command(name, data))
    while True:
        frame = ws.receive_json()
        if frame.get("type") in ("ack", "error"):
            return frame


def test_a_bot_with_the_send_scope_posts_edits_reacts_and_deletes(client: TestClient):
    owner, owner_token = _user("owner", owner=True)
    channel = _channel(owner)
    token = _create(client, owner_token, "poster", ["send_messages"])["token"]

    with client.websocket_connect(f"/ws?protocol=1&auth_token={token}") as ws:
        ws.receive_json()  # hello
        created = _send(ws, "message.create", {"channel_id": channel, "content": "beep"})
        assert created["type"] == "ack"
        message = created["data"]["result"]["message"]
        assert message["author_name"] == "poster" and message["author_id"].startswith("bot:")

        reacted = _send(ws, "reaction.add", {"channel_id": channel, "message_id": message["id"], "emoji": "🎉"})
        assert reacted["type"] == "ack" and reacted["data"]["result"]["changed"] is True
        summary = reacted["data"]["result"]["reactions"]
        assert summary[0]["emoji"] == "🎉" and summary[0]["count"] == 1 and summary[0]["viewer_reacted"] is True
        assert summary[0]["user_ids"] == [message["author_id"]]

        again = _send(ws, "reaction.add", {"channel_id": channel, "message_id": message["id"], "emoji": "🎉"})
        assert again["data"]["result"]["changed"] is False  # once per emoji, like a user

        removed = _send(ws, "reaction.remove", {"channel_id": channel, "message_id": message["id"], "emoji": "🎉"})
        assert removed["data"]["result"]["changed"] is True and removed["data"]["result"]["reactions"] == []

        edited = _send(ws, "message.edit", {"channel_id": channel, "message_id": message["id"], "content": "boop"})
        assert edited["type"] == "ack" and edited["data"]["result"]["content"] == "boop"
        deleted = _send(ws, "message.delete", {"channel_id": channel, "message_id": message["id"]})
        assert deleted["type"] == "ack"


def test_bot_and_user_reactions_share_one_summary(client: TestClient):
    owner, owner_token = _user("owner", owner=True)
    channel = _channel(owner)
    token = _create(client, owner_token, "poster", ["send_messages"])["token"]
    bot = api_initializer.bot_principal_resolver.resolve(token)
    owner_principal = api_initializer.user_principal_resolver.resolve(owner_token)

    sent = api_initializer.message_service.create(owner_principal, channel, "react to me")
    message_id = sent.value["message"]["id"]
    api_initializer.message_service.add_reaction(owner_principal, channel, message_id, "👍")
    result = api_initializer.message_service.add_reaction(bot, channel, message_id, "👍")

    [summary] = result.value["reactions"]
    assert summary["emoji"] == "👍" and summary["count"] == 2
    assert set(summary["user_ids"]) == {owner_principal.id, bot.id}
    # and history shows both, to anyone reading it
    history = api_initializer.message_service.recent(owner_principal, channel, 10)
    assert history[0]["reactions"][0]["count"] == 2


def test_a_bot_without_the_send_scope_can_read_but_not_write_or_react(client: TestClient):
    owner, owner_token = _user("owner", owner=True)
    channel = _channel(owner)
    mute_token = _create(client, owner_token, "mute", [])["token"]
    owner_principal = api_initializer.user_principal_resolver.resolve(owner_token)
    target = api_initializer.message_service.create(owner_principal, channel, "hello").value["message"]["id"]

    with client.websocket_connect(f"/ws?protocol=1&auth_token={mute_token}") as ws:
        ws.receive_json()
        for name, data in (
            ("message.create", {"channel_id": channel, "content": "nope"}),
            ("reaction.add", {"channel_id": channel, "message_id": target, "emoji": "👍"}),
        ):
            reply = _send(ws, name, data)
            assert reply["type"] == "error" and reply["error"]["code"] == "PERMISSION_DENIED", (name, reply)
        history = _send(ws, "events.resync", {"channel_id": channel, "limit": 10})
        assert history["type"] == "ack" and history["data"]["result"]["messages"][0]["content"] == "hello"


def test_a_bot_may_only_touch_its_own_messages(client: TestClient):
    owner, owner_token = _user("owner", owner=True)
    channel = _channel(owner)
    token = _create(client, owner_token, "poster", ["send_messages"])["token"]
    owner_principal = api_initializer.user_principal_resolver.resolve(owner_token)
    owners_message = api_initializer.message_service.create(owner_principal, channel, "mine").value["message"]["id"]

    with client.websocket_connect(f"/ws?protocol=1&auth_token={token}") as ws:
        ws.receive_json()
        edit = _send(ws, "message.edit", {"channel_id": channel, "message_id": owners_message, "content": "hijacked"})
        delete = _send(ws, "message.delete", {"channel_id": channel, "message_id": owners_message})

    assert edit["type"] == "error" and edit["error"]["code"] == "PERMISSION_DENIED"
    assert delete["type"] == "error" and delete["error"]["code"] == "PERMISSION_DENIED"


def test_private_channels_need_the_scope_and_the_scope_is_checked_on_every_session(client: TestClient):
    owner, owner_token = _user("owner", owner=True)
    private = _channel(owner, private=True)
    without = _create(client, owner_token, "outsider", ["send_messages"])["token"]
    with_scope = _create(client, owner_token, "insider", ["send_messages", "view_private_channels"])["token"]

    with client.websocket_connect(f"/ws?protocol=1&auth_token={without}") as ws:
        ws.receive_json()
        denied = _send(ws, "channel.subscribe", {"channel_id": private})
        assert denied["type"] == "error"
        refused_send = _send(ws, "message.create", {"channel_id": private, "content": "let me in"})
        assert refused_send["type"] == "error"

    with client.websocket_connect(f"/ws?protocol=1&auth_token={with_scope}") as ws:
        ws.receive_json()
        assert _send(ws, "channel.subscribe", {"channel_id": private})["type"] == "ack"
        assert _send(ws, "message.create", {"channel_id": private, "content": "hello from inside"})["type"] == "ack"


def test_a_revoked_bot_cannot_connect_and_a_connected_one_is_cut_off(client: TestClient):
    owner, owner_token = _user("owner", owner=True)
    channel = _channel(owner)
    created = _create(client, owner_token)
    token, bot_id = created["token"], created["bot"]["bot_id"]

    with client.websocket_connect(f"/ws?protocol=1&auth_token={token}") as ws:
        ws.receive_json()
        assert _send(ws, "message.create", {"channel_id": channel, "content": "before"})["type"] == "ack"
        assert client.delete(f"{BOTS}/{bot_id}", params={"auth_token": owner_token}).status_code == 200
        after = _send(ws, "message.create", {"channel_id": channel, "content": "after"})  # the credential is re-checked per command
        assert after["type"] == "error" and after["error"]["code"] == "UNAUTHENTICATED"
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws?protocol=1&auth_token={token}"):
            pass
