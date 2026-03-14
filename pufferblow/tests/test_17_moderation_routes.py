from __future__ import annotations

import json

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


def _create_channel(client: TestClient, owner_token: str, name: str = "moderation-room") -> str:
    response = client.post(
        "/api/v1/channels/create/",
        json={
            "auth_token": owner_token,
            "channel_name": name,
            "is_private": False,
            "channel_type": "text",
        },
    )
    assert response.status_code == 200
    return response.json()["channel_data"]["channel_id"]


def _send_message(
    client: TestClient,
    *,
    channel_id: str,
    auth_token: str,
    message: str,
):
    return client.post(
        f"/api/v1/channels/{channel_id}/send_message",
        data={"auth_token": auth_token, "message": message},
    )


def test_message_report_route_creates_audit_entry(client: TestClient):
    _, owner_token = _create_session_user(
        "report_owner",
        "owner-password",
        is_owner=True,
    )
    reporter, reporter_token = _create_session_user(
        "reporter_user",
        "reporter-password",
    )

    channel_id = _create_channel(client, owner_token, "reporting-channel")
    message_response = _send_message(
        client,
        channel_id=channel_id,
        auth_token=reporter_token,
        message="this message should be reported",
    )
    assert message_response.status_code == 200 or message_response.status_code == 201
    message_id = message_response.json()["message_id"]

    report_response = client.post(
        "/api/v1/moderation/reports/messages",
        json={
            "auth_token": reporter_token,
            "message_ids": [message_id],
            "category": "Harassment or Bullying",
            "description": "Needs moderation review",
        },
    )
    assert report_response.status_code == 201
    assert report_response.json()["reported_count"] == 1

    audit_entries = api_initializer.database_handler.list_activity_audit_entries(
        activity_types=["message_report_submitted"],
        limit=20,
    )
    assert audit_entries
    metadata = json.loads(audit_entries[0].metadata_json or "{}")
    assert message_id in metadata.get("message_ids", [])
    assert str(metadata.get("reporter_user_id")) == str(reporter.user_id)


def test_user_report_route_creates_audit_entry(client: TestClient):
    _, owner_token = _create_session_user(
        "user_report_owner",
        "owner-password",
        is_owner=True,
    )
    target_user, _ = _create_session_user(
        "reported_profile",
        "member-password",
    )

    response = client.post(
        "/api/v1/moderation/reports/users",
        json={
            "auth_token": owner_token,
            "target_user_id": str(target_user.user_id),
            "category": "Harassment or Bullying",
            "description": "Escalating profile report",
        },
    )
    assert response.status_code == 201

    audit_entries = api_initializer.database_handler.list_activity_audit_entries(
        activity_types=["user_report_submitted"],
        limit=20,
    )
    assert audit_entries
    metadata = json.loads(audit_entries[0].metadata_json or "{}")
    assert str(metadata.get("target_user_id")) == str(target_user.user_id)


def test_timeout_blocks_sending_messages_until_cleared(client: TestClient):
    _, owner_token = _create_session_user(
        "timeout_owner",
        "owner-password",
        is_owner=True,
    )
    target_user, target_token = _create_session_user(
        "timed_out_user",
        "member-password",
    )

    channel_id = _create_channel(client, owner_token, "timeout-channel")

    timeout_response = client.post(
        f"/api/v1/moderation/users/{target_user.user_id}/timeout",
        json={
            "auth_token": owner_token,
            "duration_minutes": 30,
            "reason": "Cooling off period",
        },
    )
    assert timeout_response.status_code == 201

    blocked_send = _send_message(
        client,
        channel_id=channel_id,
        auth_token=target_token,
        message="should not send while timed out",
    )
    assert blocked_send.status_code == 403
    assert "timed out" in blocked_send.json()["detail"].lower()

    clear_response = client.delete(
        f"/api/v1/moderation/users/{target_user.user_id}/timeout",
        params={"auth_token": owner_token},
    )
    assert clear_response.status_code == 200

    allowed_send = _send_message(
        client,
        channel_id=channel_id,
        auth_token=target_token,
        message="allowed again after timeout clears",
    )
    assert allowed_send.status_code == 200 or allowed_send.status_code == 201


def test_ban_blocks_profile_and_signin_until_unbanned(client: TestClient):
    _, owner_token = _create_session_user(
        "ban_owner",
        "owner-password",
        is_owner=True,
    )
    banned_user, banned_user_token = _create_session_user(
        "banned_member",
        "member-password",
    )

    ban_response = client.post(
        f"/api/v1/moderation/users/{banned_user.user_id}/ban",
        json={
            "auth_token": owner_token,
            "reason": "Repeated abuse",
        },
    )
    assert ban_response.status_code == 201

    signin_denied = client.get(
        "/api/v1/users/signin",
        params={"username": "banned_member", "password": "member-password"},
    )
    assert signin_denied.status_code == 403

    profile_denied = client.post(
        "/api/v1/users/profile",
        json={"auth_token": banned_user_token},
    )
    assert profile_denied.status_code == 403

    unban_response = client.delete(
        f"/api/v1/moderation/users/{banned_user.user_id}/ban",
        params={"auth_token": owner_token},
    )
    assert unban_response.status_code == 200

    profile_allowed = client.post(
        "/api/v1/users/profile",
        json={"auth_token": banned_user_token},
    )
    assert profile_allowed.status_code == 200
