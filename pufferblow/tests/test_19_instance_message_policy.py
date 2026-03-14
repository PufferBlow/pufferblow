from __future__ import annotations

from types import SimpleNamespace

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


def _create_channel(client: TestClient, owner_token: str, name: str = "policy-room") -> str:
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


def _policy_settings(**overrides):
    defaults = {
        "max_message_length": 50_000,
        "max_image_size": 5,
        "max_video_size": 50,
        "max_sticker_size": 5,
        "max_gif_size": 10,
        "allowed_images_extensions": ["png", "jpg", "jpeg", "gif", "webp"],
        "allowed_videos_extensions": ["mp4", "webm"],
        "allowed_doc_extensions": ["pdf", "doc", "docx", "txt", "zip"],
        "allowed_stickers_extensions": ["png", "gif"],
        "allowed_gif_extensions": ["gif"],
        "rate_limit_duration": 5,
        "max_rate_limit_requests": 6000,
        "max_rate_limit_warnings": 15,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_server_info_exposes_instance_message_and_upload_policy(client: TestClient):
    response = client.get("/api/v1/system/server-info")

    assert response.status_code == 200
    payload = response.json()["server_info"]
    assert "max_message_length" in payload
    assert "max_image_size" in payload
    assert "max_video_size" in payload
    assert "max_file_size" in payload
    assert "max_audio_size" in payload
    assert "max_total_attachment_size" in payload
    assert isinstance(payload.get("allowed_image_types"), list)
    assert isinstance(payload.get("allowed_video_types"), list)
    assert isinstance(payload.get("allowed_file_types"), list)
    assert isinstance(payload.get("allowed_audio_types"), list)


def test_send_message_uses_instance_max_message_length(client: TestClient):
    _, owner_token = _create_session_user(
        "policy_owner",
        "owner-password",
        is_owner=True,
    )
    channel_id = _create_channel(client, owner_token, "message-policy-room")

    original_get_server_settings = api_initializer.database_handler.get_server_settings
    api_initializer.database_handler.get_server_settings = lambda: _policy_settings(
        max_message_length=5,
    )

    try:
        response = client.post(
            f"/api/v1/channels/{channel_id}/send_message",
            data={
                "auth_token": owner_token,
                "message": "too long for the instance",
            },
        )
    finally:
        api_initializer.database_handler.get_server_settings = original_get_server_settings

    assert response.status_code == 400
    assert "instance limit" in response.json()["detail"].lower()


def test_send_message_attachment_rejections_surface_as_client_errors(client: TestClient):
    _, owner_token = _create_session_user(
        "policy_attachment_owner",
        "owner-password",
        is_owner=True,
    )
    channel_id = _create_channel(client, owner_token, "attachment-policy-room")

    original_get_server_settings = api_initializer.database_handler.get_server_settings
    api_initializer.database_handler.get_server_settings = lambda: _policy_settings(
        allowed_doc_extensions=["txt"],
    )

    try:
        response = client.post(
            f"/api/v1/channels/{channel_id}/send_message",
            data={
                "auth_token": owner_token,
                "message": "uploading a blocked attachment",
            },
            files={
                "attachments": ("blocked.pdf", b"%PDF-1.4 test payload", "application/pdf"),
            },
        )
    finally:
        api_initializer.database_handler.get_server_settings = original_get_server_settings

    assert response.status_code == 400
    assert "not allowed" in response.json()["detail"].lower()
