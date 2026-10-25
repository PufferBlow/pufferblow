from fastapi.testclient import TestClient

from pufferblow.core.bootstrap import api_initializer


def _user(username: str, *, owner: bool = False):
    user = api_initializer.user_manager.sign_up(username=username, password="a-long-password", is_owner=owner)
    tokens = api_initializer.auth_token_manager.issue_session_tokens(
        user_id=str(user.user_id), origin_server=user.origin_server
    )
    return user, tokens["access_token"]


def _setup(client: TestClient, tag: str):
    _, owner_token = _user(f"owner_{tag}", owner=True)
    _, other_token = _user(f"other_{tag}")
    channel_id = client.post(
        "/api/v1/channels/create/",
        json={"auth_token": owner_token, "channel_name": f"room-{tag}", "is_private": False, "channel_type": "text"},
    ).json()["channel_data"]["channel_id"]
    return owner_token, other_token, channel_id


def _send(client: TestClient, token: str, channel_id: str, text: str, reply_to: str | None = None) -> str:
    data = {"auth_token": token, "message": text}
    if reply_to:
        data["reply_to_message_id"] = reply_to
    response = client.post(f"/api/v1/channels/{channel_id}/send_message", data=data)
    assert response.status_code == 200 or response.status_code == 201, response.text
    return response.json()["message_id"]


def _notifications(client: TestClient, token: str) -> list[dict]:
    return client.get("/api/v1/notifications/", params={"auth_token": token}).json()["notifications"]


def test_replying_to_someone_notifies_them(client: TestClient):
    owner, other, channel = _setup(client, "reply")
    original = _send(client, owner, channel, "anyone around?")

    reply = _send(client, other, channel, "yes!", reply_to=original)

    [note] = _notifications(client, owner)
    assert note["type"] == "reply"
    assert note["channel_id"] == channel
    assert note["message_id"] == reply
    assert _notifications(client, other) == []


def test_replying_to_yourself_notifies_nobody(client: TestClient):
    owner, _, channel = _setup(client, "self")
    original = _send(client, owner, channel, "note to self")
    _send(client, owner, channel, "and another", reply_to=original)
    assert _notifications(client, owner) == []


def test_someone_already_getting_a_mention_is_not_pinged_twice(client: TestClient):
    owner, other, channel = _setup(client, "both")
    original = _send(client, owner, channel, "hello")
    owner_id = str(api_initializer.database_handler.get_user(username="owner_both").user_id)
    other_id = str(api_initializer.database_handler.get_user(username="other_both").user_id)
    notifications = api_initializer.notifications_manager

    # The reply notification is skipped when the same message already mentions the author.
    assert notifications.record_reply_for_message(
        sender_user_id=other_id,
        channel_id=channel,
        message_id=original,
        reply_to_message_id=original,
        already_notified={owner_id},
    ) == []


def test_a_notification_carries_a_short_look_at_its_message(client: TestClient):
    owner, other, channel = _setup(client, "preview")
    original = _send(client, owner, channel, "anyone around?")
    long_text = "yes! " + "word " * 100
    _send(client, other, channel, long_text, reply_to=original)

    [note] = _notifications(client, owner)

    assert note["preview"]["text"].startswith("yes! word word")
    assert 0 < len(note["preview"]["text"]) <= 200  # cut, not the whole message
    assert note["preview"]["has_attachments"] is False


def test_the_preview_is_left_out_once_the_viewer_can_no_longer_read_the_channel(client: TestClient, monkeypatch):
    owner, other, channel = _setup(client, "revoked")
    original = _send(client, owner, channel, "anyone around?")
    _send(client, other, channel, "a private reply", reply_to=original)

    def refuse(user_id, channel_id):
        raise PermissionError("no access")

    monkeypatch.setattr("pufferblow.api.routes.notifications.check_channel_access", refuse)
    [note] = _notifications(client, owner)
    assert "preview" not in note
