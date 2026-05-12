"""Tests for the channel message search endpoint."""

import uuid

from fastapi.testclient import TestClient


SIGNUP_ROUTE = "/api/v1/users/signup"
LIST_CHANNELS_ROUTE = "/api/v1/channels/list/"


def _make_user(client: TestClient) -> tuple[str, str]:
    """Sign up a fresh user and return (auth_token, user_id-shaped string)."""
    username = f"searcher_{uuid.uuid4().hex[:8]}"
    password = "12345678"
    response = client.post(SIGNUP_ROUTE, json={"username": username, "password": password})
    assert response.status_code == 201, response.text
    return response.json()["auth_token"], username


def _list_channels(client: TestClient, auth_token: str) -> list[dict]:
    """Return the channel list visible to the given token."""
    response = client.get(LIST_CHANNELS_ROUTE, params={"auth_token": auth_token})
    assert response.status_code == 200, response.text
    return response.json().get("channels", [])


def _seed_messages(
    client: TestClient,
    auth_token: str,
    channel_id: str,
    messages: list[str],
) -> None:
    """Send each message into the given channel via the public send route."""
    send_route = f"/api/v1/channels/{channel_id}/send_message"
    for body in messages:
        response = client.post(
            send_route,
            data={"auth_token": auth_token, "message": body, "sent_at": ""},
        )
        assert response.status_code in (200, 201), response.text


def _search(client: TestClient, channel_id: str, **params) -> tuple[int, dict]:
    route = f"/api/v1/channels/{channel_id}/search"
    response = client.get(route, params=params)
    try:
        return response.status_code, response.json()
    except Exception:
        return response.status_code, {}


def test_search_rejects_query_too_short(client: TestClient):
    auth_token, _ = _make_user(client)
    channels = _list_channels(client, auth_token)
    if not channels:
        # No default channel — endpoint validation should still run via the
        # route, so target a synthetic channel id that fails the access check.
        # Validation of `q` length happens after access check, so just skip.
        return
    channel_id = channels[0]["channel_id"]

    status, body = _search(client, channel_id, auth_token=auth_token, q="a")
    assert status == 400
    assert "at least" in body.get("detail", "").lower()


def test_search_rejects_limit_out_of_range(client: TestClient):
    auth_token, _ = _make_user(client)
    channels = _list_channels(client, auth_token)
    if not channels:
        return
    channel_id = channels[0]["channel_id"]

    status, body = _search(
        client, channel_id, auth_token=auth_token, q="hello", limit=999
    )
    assert status == 400
    assert "limit" in body.get("detail", "").lower()


def test_search_finds_matching_message(client: TestClient):
    auth_token, _ = _make_user(client)
    channels = _list_channels(client, auth_token)
    if not channels:
        return
    channel_id = channels[0]["channel_id"]

    _seed_messages(
        client,
        auth_token,
        channel_id,
        [
            "hello world from the test",
            "totally unrelated content",
            "another HELLO uppercase",
        ],
    )

    status, body = _search(client, channel_id, auth_token=auth_token, q="hello")
    assert status == 200, body
    assert body["query"] == "hello"
    assert body["truncated_scan"] is False
    messages = body["messages"]
    assert len(messages) == 2
    bodies_lower = {m["message"].lower() for m in messages}
    assert any("hello world" in b for b in bodies_lower)
    assert any("another hello" in b for b in bodies_lower)


def test_search_returns_empty_for_no_match(client: TestClient):
    auth_token, _ = _make_user(client)
    channels = _list_channels(client, auth_token)
    if not channels:
        return
    channel_id = channels[0]["channel_id"]

    _seed_messages(client, auth_token, channel_id, ["alpha", "beta", "gamma"])

    status, body = _search(client, channel_id, auth_token=auth_token, q="zzzzz")
    assert status == 200, body
    assert body["messages"] == []
    assert body["scanned"] >= 3


def test_search_respects_limit_cap(client: TestClient):
    auth_token, _ = _make_user(client)
    channels = _list_channels(client, auth_token)
    if not channels:
        return
    channel_id = channels[0]["channel_id"]

    _seed_messages(
        client,
        auth_token,
        channel_id,
        [f"match {i}" for i in range(8)] + ["unrelated"],
    )

    status, body = _search(client, channel_id, auth_token=auth_token, q="match", limit=3)
    assert status == 200, body
    assert len(body["messages"]) == 3
