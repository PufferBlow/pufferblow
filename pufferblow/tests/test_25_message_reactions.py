"""Tests for message reaction lifecycle (add, remove, idempotency, summary)."""

import uuid

from fastapi.testclient import TestClient


SIGNUP_ROUTE = "/api/v1/users/signup"
LIST_CHANNELS_ROUTE = "/api/v1/channels/list/"


def _make_user(client: TestClient) -> str:
    username = f"reactor_{uuid.uuid4().hex[:8]}"
    response = client.post(
        SIGNUP_ROUTE, json={"username": username, "password": "12345678"}
    )
    assert response.status_code == 201, response.text
    return response.json()["auth_token"]


def _first_channel_id(client: TestClient, auth_token: str) -> str | None:
    response = client.get(LIST_CHANNELS_ROUTE, params={"auth_token": auth_token})
    assert response.status_code == 200, response.text
    channels = response.json().get("channels", [])
    return channels[0]["channel_id"] if channels else None


def _send(client: TestClient, channel_id: str, auth_token: str, body: str) -> str:
    response = client.post(
        f"/api/v1/channels/{channel_id}/send_message",
        data={"auth_token": auth_token, "message": body, "sent_at": ""},
    )
    assert response.status_code in (200, 201), response.text
    return response.json()["message_id"]


def _add(client: TestClient, channel_id: str, message_id: str, auth_token: str, emoji: str):
    return client.post(
        f"/api/v1/channels/{channel_id}/messages/{message_id}/reactions",
        params={"auth_token": auth_token, "emoji": emoji},
    )


def _remove(client: TestClient, channel_id: str, message_id: str, auth_token: str, emoji: str):
    return client.delete(
        f"/api/v1/channels/{channel_id}/messages/{message_id}/reactions",
        params={"auth_token": auth_token, "emoji": emoji},
    )


def test_add_reaction_returns_201_and_summary(client: TestClient):
    auth_token = _make_user(client)
    channel_id = _first_channel_id(client, auth_token)
    if not channel_id:
        return
    message_id = _send(client, channel_id, auth_token, "react to me")

    response = _add(client, channel_id, message_id, auth_token, "👍")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["already_present"] is False
    assert body["emoji"] == "👍"
    assert len(body["reactions"]) == 1
    summary = body["reactions"][0]
    assert summary["emoji"] == "👍"
    assert summary["count"] == 1
    assert summary["viewer_reacted"] is True


def test_add_reaction_is_idempotent(client: TestClient):
    auth_token = _make_user(client)
    channel_id = _first_channel_id(client, auth_token)
    if not channel_id:
        return
    message_id = _send(client, channel_id, auth_token, "idempotent target")

    first = _add(client, channel_id, message_id, auth_token, "🎉")
    assert first.status_code == 201
    second = _add(client, channel_id, message_id, auth_token, "🎉")
    assert second.status_code == 200
    body = second.json()
    assert body["already_present"] is True
    assert body["reactions"][0]["count"] == 1


def test_remove_reaction_returns_summary_without_emoji(client: TestClient):
    auth_token = _make_user(client)
    channel_id = _first_channel_id(client, auth_token)
    if not channel_id:
        return
    message_id = _send(client, channel_id, auth_token, "remove target")
    add_response = _add(client, channel_id, message_id, auth_token, "🔥")
    assert add_response.status_code == 201

    response = _remove(client, channel_id, message_id, auth_token, "🔥")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["already_absent"] is False
    assert body["reactions"] == []


def test_remove_reaction_is_idempotent(client: TestClient):
    auth_token = _make_user(client)
    channel_id = _first_channel_id(client, auth_token)
    if not channel_id:
        return
    message_id = _send(client, channel_id, auth_token, "never reacted")

    response = _remove(client, channel_id, message_id, auth_token, "🤷")
    assert response.status_code == 200, response.text
    assert response.json()["already_absent"] is True
    assert response.json()["reactions"] == []


def test_user_can_apply_multiple_distinct_emoji(client: TestClient):
    auth_token = _make_user(client)
    channel_id = _first_channel_id(client, auth_token)
    if not channel_id:
        return
    message_id = _send(client, channel_id, auth_token, "multi-emoji target")

    for emoji in ("👍", "🎉", "💯"):
        response = _add(client, channel_id, message_id, auth_token, emoji)
        assert response.status_code == 201, (emoji, response.text)

    response = _add(client, channel_id, message_id, auth_token, "✨")
    body = response.json()
    emojis = {entry["emoji"] for entry in body["reactions"]}
    assert emojis == {"👍", "🎉", "💯", "✨"}
    assert all(entry["count"] == 1 for entry in body["reactions"])


def test_empty_emoji_rejected(client: TestClient):
    auth_token = _make_user(client)
    channel_id = _first_channel_id(client, auth_token)
    if not channel_id:
        return
    message_id = _send(client, channel_id, auth_token, "empty target")

    response = _add(client, channel_id, message_id, auth_token, "")
    assert response.status_code == 400


def test_over_long_emoji_rejected(client: TestClient):
    auth_token = _make_user(client)
    channel_id = _first_channel_id(client, auth_token)
    if not channel_id:
        return
    message_id = _send(client, channel_id, auth_token, "long target")

    too_long = "a" * 64
    response = _add(client, channel_id, message_id, auth_token, too_long)
    assert response.status_code == 400


def test_load_messages_includes_reactions(client: TestClient):
    auth_token = _make_user(client)
    channel_id = _first_channel_id(client, auth_token)
    if not channel_id:
        return
    message_id = _send(client, channel_id, auth_token, "hydration target")
    _add(client, channel_id, message_id, auth_token, "🚀")

    response = client.get(
        f"/api/v1/channels/{channel_id}/load_messages",
        params={"auth_token": auth_token, "page": 1, "messages_per_page": 20},
    )
    assert response.status_code == 200, response.text
    messages = response.json()["messages"]
    target = next((m for m in messages if m["message_id"] == message_id), None)
    assert target is not None
    assert target["reactions"][0]["emoji"] == "🚀"
    assert target["reactions"][0]["viewer_reacted"] is True
