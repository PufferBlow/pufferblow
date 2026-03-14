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


def test_owner_can_create_and_list_custom_roles(client: TestClient):
    owner, owner_token = _create_session_user(
        "instance_owner",
        "owner-password",
        is_owner=True,
    )

    create_response = client.post(
        "/api/v1/system/roles",
        json={
            "auth_token": owner_token,
            "role_name": "Channel Steward",
            "privileges_ids": [
                "create_channels",
                "view_private_channels",
            ],
        },
    )
    assert create_response.status_code == 201
    create_payload = create_response.json()
    assert create_payload["role"]["role_id"] == "channel-steward"
    assert create_payload["role"]["is_system"] is False

    roles_response = client.post(
        "/api/v1/system/roles/list",
        json={"auth_token": owner_token},
    )
    assert roles_response.status_code == 200
    role_ids = {role["role_id"] for role in roles_response.json()["roles"]}
    assert {"owner", "admin", "moderator", "user", "channel-steward"} <= role_ids

    privileges_response = client.post(
        "/api/v1/system/privileges/list",
        json={"auth_token": owner_token},
    )
    assert privileges_response.status_code == 200
    privilege_ids = {
        privilege["privilege_id"]
        for privilege in privileges_response.json()["privileges"]
    }
    assert "create_channels" in privilege_ids
    assert "manage_server_privileges" in privilege_ids
    assert "manage_blocked_ips" in privilege_ids
    assert "manage_background_tasks" in privilege_ids


def test_non_owner_cannot_create_custom_roles(client: TestClient):
    _, member_token = _create_session_user(
        "plain_member",
        "member-password",
    )

    response = client.post(
        "/api/v1/system/roles",
        json={
            "auth_token": member_token,
            "role_name": "Helpers",
            "privileges_ids": ["create_channels"],
        },
    )

    assert response.status_code == 403


def test_custom_role_privileges_are_enforced_on_channel_creation(client: TestClient):
    _, owner_token = _create_session_user(
        "role_owner",
        "owner-password",
        is_owner=True,
    )
    member, member_token = _create_session_user(
        "channel_builder",
        "member-password",
    )

    role_response = client.post(
        "/api/v1/system/roles",
        json={
            "auth_token": owner_token,
            "role_name": "Builders",
            "privileges_ids": ["create_channels"],
        },
    )
    assert role_response.status_code == 201
    role_id = role_response.json()["role"]["role_id"]

    denied_response = client.post(
        "/api/v1/channels/create/",
        json={
            "auth_token": member_token,
            "channel_name": "custom-role-room",
            "is_private": False,
            "channel_type": "text",
        },
    )
    assert denied_response.status_code == 403

    assign_response = client.put(
        f"/api/v1/system/users/{member.user_id}/roles",
        json={
            "auth_token": owner_token,
            "roles_ids": ["user", role_id],
        },
    )
    assert assign_response.status_code == 200
    assert set(assign_response.json()["user"]["roles_ids"]) == {"user", role_id}

    allowed_response = client.post(
        "/api/v1/channels/create/",
        json={
            "auth_token": member_token,
            "channel_name": "custom-role-room",
            "is_private": False,
            "channel_type": "text",
        },
    )
    assert allowed_response.status_code == 200
    assert allowed_response.json()["channel_data"]["channel_name"] == "custom-role-room"


def test_custom_role_privileges_allow_instance_logs_access(client: TestClient):
    _, owner_token = _create_session_user(
        "logs_owner",
        "owner-password",
        is_owner=True,
    )
    member, member_token = _create_session_user(
        "logs_reader",
        "member-password",
    )

    role_response = client.post(
        "/api/v1/system/roles",
        json={
            "auth_token": owner_token,
            "role_name": "Audit Readers",
            "privileges_ids": ["view_audit_logs"],
        },
    )
    assert role_response.status_code == 201
    role_id = role_response.json()["role"]["role_id"]

    denied_response = client.post(
        "/api/v1/system/logs",
        json={
            "auth_token": member_token,
            "lines": 10,
        },
    )
    assert denied_response.status_code == 403

    assign_response = client.put(
        f"/api/v1/system/users/{member.user_id}/roles",
        json={
            "auth_token": owner_token,
            "roles_ids": ["user", role_id],
        },
    )
    assert assign_response.status_code == 200

    allowed_response = client.post(
        "/api/v1/system/logs",
        json={
            "auth_token": member_token,
            "lines": 10,
        },
    )
    assert allowed_response.status_code == 200
    assert "logs" in allowed_response.json()
