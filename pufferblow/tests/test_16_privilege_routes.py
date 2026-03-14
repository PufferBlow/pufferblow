from __future__ import annotations

from pathlib import Path
from types import MethodType

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


def _create_role(client: TestClient, owner_token: str, role_name: str, privileges: list[str]) -> str:
    response = client.post(
        "/api/v1/system/roles",
        json={
            "auth_token": owner_token,
            "role_name": role_name,
            "privileges_ids": privileges,
        },
    )
    assert response.status_code == 201
    return response.json()["role"]["role_id"]


def _assign_role(
    client: TestClient,
    owner_token: str,
    user_id: str,
    role_id: str,
) -> None:
    response = client.put(
        f"/api/v1/system/users/{user_id}/roles",
        json={
            "auth_token": owner_token,
            "roles_ids": ["user", role_id],
        },
    )
    assert response.status_code == 200


def test_manage_server_settings_privilege_allows_runtime_config_access(client: TestClient):
    _, owner_token = _create_session_user(
        "runtime_owner",
        "owner-password",
        is_owner=True,
    )
    member, member_token = _create_session_user(
        "runtime_editor",
        "member-password",
    )

    denied_response = client.post(
        "/api/v1/system/runtime-config",
        json={"auth_token": member_token, "include_secrets": True},
    )
    assert denied_response.status_code == 403

    role_id = _create_role(
        client,
        owner_token,
        "Runtime Editors",
        ["manage_server_settings"],
    )
    _assign_role(client, owner_token, str(member.user_id), role_id)

    allowed_response = client.post(
        "/api/v1/system/runtime-config",
        json={"auth_token": member_token, "include_secrets": True},
    )
    assert allowed_response.status_code == 200
    payload = allowed_response.json()
    assert payload["include_secrets"] is False
    assert "runtime_config" in payload
    assert "WORKERS" in payload["runtime_config"]


def test_view_server_stats_privilege_allows_metrics_and_overview_routes(client: TestClient):
    _, owner_token = _create_session_user(
        "stats_owner",
        "owner-password",
        is_owner=True,
    )
    member, member_token = _create_session_user(
        "stats_reader",
        "member-password",
    )

    denied_metrics = client.post(
        "/api/v1/system/activity-metrics",
        json={"auth_token": member_token},
    )
    denied_overview = client.post(
        "/api/v1/system/server-overview",
        json={"auth_token": member_token},
    )
    assert denied_metrics.status_code == 403
    assert denied_overview.status_code == 403

    role_id = _create_role(
        client,
        owner_token,
        "Stats Readers",
        ["view_server_stats"],
    )
    _assign_role(client, owner_token, str(member.user_id), role_id)

    allowed_metrics = client.post(
        "/api/v1/system/activity-metrics",
        json={"auth_token": member_token},
    )
    allowed_overview = client.post(
        "/api/v1/system/server-overview",
        json={"auth_token": member_token},
    )

    assert allowed_metrics.status_code == 200
    assert "activity_metrics" in allowed_metrics.json()
    assert allowed_overview.status_code == 200
    overview = allowed_overview.json()["server_overview"]
    assert "total_users" in overview
    assert "total_channels" in overview


def test_view_audit_logs_privilege_allows_recent_activity_route(client: TestClient):
    _, owner_token = _create_session_user(
        "activity_owner",
        "owner-password",
        is_owner=True,
    )
    member, member_token = _create_session_user(
        "activity_reader",
        "member-password",
    )

    denied_response = client.post(
        "/api/v1/system/recent-activity",
        json={"auth_token": member_token, "limit": 5},
    )
    assert denied_response.status_code == 403

    role_id = _create_role(
        client,
        owner_token,
        "Activity Readers",
        ["view_audit_logs"],
    )
    _assign_role(client, owner_token, str(member.user_id), role_id)

    allowed_response = client.post(
        "/api/v1/system/recent-activity",
        json={"auth_token": member_token, "limit": 5},
    )
    assert allowed_response.status_code == 200
    assert "activities" in allowed_response.json()


def test_storage_privileges_gate_list_file_info_delete_and_cleanup(
    client: TestClient,
    tmp_path: Path,
):
    _, owner_token = _create_session_user(
        "storage_owner",
        "owner-password",
        is_owner=True,
    )
    member, member_token = _create_session_user(
        "storage_manager",
        "member-password",
    )

    api_initializer.config.STORAGE_PATH = str(tmp_path)
    api_initializer.storage_manager.STORAGE_PATH = str(tmp_path)
    api_initializer.storage_manager.config["storage_path"] = str(tmp_path)
    if hasattr(api_initializer.storage_manager.backend, "storage_path"):
        api_initializer.storage_manager.backend.storage_path = tmp_path

    files_dir = tmp_path / "files"
    files_dir.mkdir(parents=True, exist_ok=True)

    managed_file = files_dir / "managed.txt"
    managed_file.write_text("managed file", encoding="utf-8")

    denied_list = client.post(
        "/api/v1/storage/files",
        json={"auth_token": member_token, "directory": "files"},
    )
    denied_file_info = client.post(
        "/api/v1/storage/file-info",
        json={"auth_token": member_token, "file_url": "/api/v1/storage/file/files/managed.txt"},
    )
    denied_delete = client.post(
        "/api/v1/storage/delete-file",
        json={"auth_token": member_token, "file_url": "/api/v1/storage/file/files/managed.txt"},
    )
    denied_cleanup = client.post(
        "/api/v1/storage/cleanup-orphaned",
        json={"auth_token": member_token, "subdirectory": "files"},
    )

    assert denied_list.status_code == 200
    assert denied_file_info.status_code == 200
    assert denied_delete.status_code == 403
    assert denied_cleanup.status_code == 403

    role_id = _create_role(
        client,
        owner_token,
        "Storage Operators",
        ["view_files", "delete_files", "manage_cdn"],
    )
    _assign_role(client, owner_token, str(member.user_id), role_id)

    allowed_list = client.post(
        "/api/v1/storage/files",
        json={"auth_token": member_token, "directory": "files"},
    )
    assert allowed_list.status_code == 200
    listed_files = allowed_list.json()["files"]
    assert any(file_entry["filename"] == "managed.txt" for file_entry in listed_files)

    allowed_file_info = client.post(
        "/api/v1/storage/file-info",
        json={"auth_token": member_token, "file_url": "/api/v1/storage/file/files/managed.txt"},
    )
    assert allowed_file_info.status_code == 200
    assert allowed_file_info.json()["file_info"]["path"] == "files/managed.txt"

    allowed_delete = client.post(
        "/api/v1/storage/delete-file",
        json={"auth_token": member_token, "file_url": "/api/v1/storage/file/files/managed.txt"},
    )
    assert allowed_delete.status_code == 200
    assert not managed_file.exists()

    orphan_file = files_dir / "orphan.txt"
    orphan_file.write_text("orphaned file", encoding="utf-8")

    allowed_cleanup = client.post(
        "/api/v1/storage/cleanup-orphaned",
        json={"auth_token": member_token, "subdirectory": "files"},
    )
    assert allowed_cleanup.status_code == 200
    assert allowed_cleanup.json()["deleted_count"] >= 1
    assert not orphan_file.exists()


def test_manage_blocked_ips_privilege_allows_block_list_and_unblock(client: TestClient):
    _, owner_token = _create_session_user(
        "blocked_ip_owner",
        "owner-password",
        is_owner=True,
    )
    member, member_token = _create_session_user(
        "blocked_ip_operator",
        "member-password",
    )

    denied_list = client.post(
        "/api/v1/blocked-ips/list",
        json={"auth_token": member_token},
    )
    denied_block = client.post(
        "/api/v1/blocked-ips/block",
        json={"auth_token": member_token, "ip": "203.0.113.7", "reason": "test"},
    )
    assert denied_list.status_code == 403
    assert denied_block.status_code == 403

    role_id = _create_role(
        client,
        owner_token,
        "Blocked IP Operators",
        ["manage_blocked_ips"],
    )
    _assign_role(client, owner_token, str(member.user_id), role_id)

    allowed_block = client.post(
        "/api/v1/blocked-ips/block",
        json={
            "auth_token": member_token,
            "ip": "203.0.113.7",
            "reason": "Automated abuse test",
        },
    )
    assert allowed_block.status_code == 201

    allowed_list = client.post(
        "/api/v1/blocked-ips/list",
        json={"auth_token": member_token},
    )
    assert allowed_list.status_code == 200
    assert any(
        entry["ip"] == "203.0.113.7"
        for entry in allowed_list.json()["blocked_ips"]
    )

    allowed_unblock = client.post(
        "/api/v1/blocked-ips/unblock",
        json={"auth_token": member_token, "ip": "203.0.113.7"},
    )
    assert allowed_unblock.status_code == 200


def test_manage_background_tasks_privilege_allows_status_and_run(
    client: TestClient,
):
    _, owner_token = _create_session_user(
        "tasks_owner",
        "owner-password",
        is_owner=True,
    )
    member, member_token = _create_session_user(
        "tasks_operator",
        "member-password",
    )

    denied_status = client.post(
        "/api/v1/background-tasks/status",
        json={"auth_token": member_token},
    )
    denied_run = client.post(
        "/api/v1/background-tasks/run",
        json={"auth_token": member_token, "task_id": "cleanup_temp_files"},
    )
    assert denied_status.status_code == 403
    assert denied_run.status_code == 403

    role_id = _create_role(
        client,
        owner_token,
        "Task Operators",
        ["manage_background_tasks"],
    )
    _assign_role(client, owner_token, str(member.user_id), role_id)

    background_tasks_manager = api_initializer.background_tasks_manager

    def fake_get_task_status(self):
        return {
            "cleanup_temp_files": {
                "task_id": "cleanup_temp_files",
                "name": "Cleanup temp files",
                "status": "pending",
                "progress": 0,
            }
        }

    async def fake_run_task(self, task_id: str) -> bool:
        return task_id == "cleanup_temp_files"

    background_tasks_manager.get_task_status = MethodType(
        fake_get_task_status,
        background_tasks_manager,
    )
    background_tasks_manager.run_task = MethodType(
        fake_run_task,
        background_tasks_manager,
    )

    allowed_status = client.post(
        "/api/v1/background-tasks/status",
        json={"auth_token": member_token},
    )
    assert allowed_status.status_code == 200
    assert "cleanup_temp_files" in allowed_status.json()["tasks"]

    allowed_run = client.post(
        "/api/v1/background-tasks/run",
        json={"auth_token": member_token, "task_id": "cleanup_temp_files"},
    )
    assert allowed_run.status_code == 200


def test_storage_file_route_supports_byte_ranges_for_video_playback(
    client: TestClient,
    tmp_path: Path,
):
    api_initializer.config.STORAGE_PATH = str(tmp_path)
    api_initializer.storage_manager.STORAGE_PATH = str(tmp_path)
    api_initializer.storage_manager.config["storage_path"] = str(tmp_path)
    if hasattr(api_initializer.storage_manager.backend, "storage_path"):
        api_initializer.storage_manager.backend.storage_path = tmp_path

    videos_dir = tmp_path / "videos"
    videos_dir.mkdir(parents=True, exist_ok=True)

    video_file = videos_dir / "clip.mp4"
    video_content = b"0123456789abcdefghijklmnopqrstuvwxyz"
    video_file.write_bytes(video_content)

    partial_response = client.get(
        "/api/v1/storage/file/videos/clip.mp4",
        headers={"Range": "bytes=10-19"},
    )
    assert partial_response.status_code == 206
    assert partial_response.content == video_content[10:20]
    assert partial_response.headers["content-range"] == f"bytes 10-19/{len(video_content)}"
    assert partial_response.headers["accept-ranges"] == "bytes"
    assert partial_response.headers["content-type"].startswith("video/mp4")

    invalid_range_response = client.get(
        "/api/v1/storage/file/videos/clip.mp4",
        headers={"Range": "bytes=999-1200"},
    )
    assert invalid_range_response.status_code == 416
    assert invalid_range_response.headers["content-range"] == f"bytes */{len(video_content)}"
