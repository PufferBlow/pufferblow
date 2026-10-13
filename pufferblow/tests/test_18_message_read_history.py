from fastapi.testclient import TestClient

from pufferblow.core.bootstrap import api_initializer


def _create_session_user(
    username: str,
    password: str,
    *,
    is_owner: bool = False,
    is_admin: bool = False,
):
    user = api_initializer.user_manager.sign_up(
        username=username,
        password=password,
        is_owner=is_owner,
        is_admin=is_admin,
    )
    tokens = api_initializer.auth_token_manager.issue_session_tokens(
        user_id=str(user.user_id),
        origin_server=user.origin_server,
    )
    return user, tokens["access_token"]


def test_read_history_returns_unread_counts_for_accessible_channels(client: TestClient):
    _, sender_token = _create_session_user(
        "sender_user",
        "sender-password",
        is_owner=True,
    )
    _, reader_token = _create_session_user(
        "reader_user",
        "reader-password",
    )

    create_channel_response = client.post(
        "/api/v1/channels/create/",
        json={
            "auth_token": sender_token,
            "channel_name": "notifications-test-room",
            "is_private": False,
            "channel_type": "text",
        },
    )
    assert create_channel_response.status_code == 200
    channel_id = create_channel_response.json()["channel_data"]["channel_id"]

    send_response = client.post(
        f"/api/v1/channels/{channel_id}/send_message",
        data={
            "auth_token": sender_token,
            "message": "Hello from notifications test",
        },
    )
    assert send_response.status_code == 200
    message_id = send_response.json()["message_id"]

    history_response = client.get(
        "/api/v1/channels/read-history",
        params={"auth_token": reader_token},
    )
    assert history_response.status_code == 200
    payload = history_response.json()
    assert payload["viewed_message_ids"] == []
    assert payload["unread_counts"][channel_id] >= 1
    assert message_id not in payload["viewed_message_ids"]


def test_mark_message_as_read_updates_history_snapshot(client: TestClient):
    _, sender_token = _create_session_user(
        "sender_user_two",
        "sender-password",
        is_owner=True,
    )
    _, reader_token = _create_session_user(
        "reader_user_two",
        "reader-password",
    )

    create_channel_response = client.post(
        "/api/v1/channels/create/",
        json={
            "auth_token": sender_token,
            "channel_name": "notifications-test-room-two",
            "is_private": False,
            "channel_type": "text",
        },
    )
    assert create_channel_response.status_code == 200
    channel_id = create_channel_response.json()["channel_data"]["channel_id"]

    send_response = client.post(
        f"/api/v1/channels/{channel_id}/send_message",
        data={
            "auth_token": sender_token,
            "message": "Please mark me as read",
        },
    )
    assert send_response.status_code == 200
    message_id = send_response.json()["message_id"]

    mark_response = client.put(
        f"/api/v1/channels/{channel_id}/mark_message_as_read",
        params={
            "auth_token": reader_token,
            "message_id": message_id,
        },
    )
    assert mark_response.status_code == 200

    history_response = client.get(
        "/api/v1/channels/read-history",
        params={"auth_token": reader_token},
    )
    assert history_response.status_code == 200
    payload = history_response.json()
    assert message_id in payload["viewed_message_ids"]
    assert payload["unread_counts"].get(channel_id, 0) == 0


def test_a_new_member_has_no_unread_messages_from_before_they_joined(client: TestClient):
    _, sender_token = _create_session_user("early_sender", "sender-password", is_owner=True)

    channel_id = client.post(
        "/api/v1/channels/create/",
        json={
            "auth_token": sender_token,
            "channel_name": "before-you-joined",
            "is_private": False,
            "channel_type": "text",
        },
    ).json()["channel_data"]["channel_id"]
    client.post(
        f"/api/v1/channels/{channel_id}/send_message",
        data={"auth_token": sender_token, "message": "Said before the newcomer existed"},
    )

    # The newcomer signs up afterwards: that message is history to them, not news.
    _, newcomer_token = _create_session_user("late_joiner", "newcomer-password")
    payload = client.get("/api/v1/channels/read-history", params={"auth_token": newcomer_token}).json()
    assert payload["unread_counts"].get(channel_id, 0) == 0

    # Anything sent from then on is unread as usual.
    client.post(
        f"/api/v1/channels/{channel_id}/send_message",
        data={"auth_token": sender_token, "message": "Said after the newcomer joined"},
    )
    payload = client.get("/api/v1/channels/read-history", params={"auth_token": newcomer_token}).json()
    assert payload["unread_counts"][channel_id] == 1
