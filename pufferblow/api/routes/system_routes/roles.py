"""Instance role and privilege management routes."""

from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException

from pufferblow.api.dependencies import get_current_user
from pufferblow.api.roles.constants import DEFAULT_ROLE_ID, IMMUTABLE_ROLE_IDS
from pufferblow.api.routes.system_routes.shared import (
    log_activity,
    require_component,
    require_server_owner,
)
from pufferblow.api.schemas import (
    PrivilegeListRequest,
    RoleCreateRequest,
    RoleListRequest,
    RoleUpdateRequest,
    UserRolesUpdateRequest,
)

router = APIRouter(prefix="/api/v1/system")


def _slugify_role_name(role_name: str) -> str:
    """Generate a stable role identifier from the display name."""
    slug = re.sub(r"[^a-z0-9]+", "-", role_name.lower()).strip("-")
    return slug or "custom-role"


def _serialize_role(database_handler, role) -> dict:
    """Return a client-safe role payload."""
    return {
        "role_id": role.role_id,
        "role_name": role.role_name,
        "privileges_ids": list(role.privileges_ids or []),
        "is_system": database_handler.is_system_role(role.role_id),
        "user_count": database_handler.count_users_for_role(role.role_id),
    }


@router.post("/roles/list", status_code=200)
async def list_roles_route(request: RoleListRequest):
    """List instance roles for the active home instance."""
    get_current_user(request.auth_token)
    database_handler = require_component("database_handler")
    return {
        "status_code": 200,
        "roles": [
            _serialize_role(database_handler, role)
            for role in database_handler.list_roles()
        ],
    }


@router.post("/privileges/list", status_code=200)
async def list_privileges_route(request: PrivilegeListRequest):
    """List privileges that can be attached to custom roles."""
    require_server_owner(request.auth_token)
    database_handler = require_component("database_handler")
    return {
        "status_code": 200,
        "privileges": [
            {
                "privilege_id": privilege.privilege_id,
                "privilege_name": privilege.privilege_name,
                "category": privilege.category,
            }
            for privilege in database_handler.list_privileges()
        ],
    }


@router.post("/roles", status_code=201)
async def create_role_route(request: RoleCreateRequest):
    """Create a custom instance role."""
    owner_user_id = require_server_owner(request.auth_token)
    database_handler = require_component("database_handler")
    role_name = request.role_name.strip()
    if not role_name:
        raise HTTPException(status_code=422, detail="Role name cannot be empty.")

    valid_privileges = database_handler.get_privilege_ids()
    unknown_privileges = sorted(set(request.privileges_ids) - valid_privileges)
    if unknown_privileges:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown privileges: {', '.join(unknown_privileges)}",
        )

    role_id = _slugify_role_name(role_name)
    if role_id in IMMUTABLE_ROLE_IDS:
        raise HTTPException(
            status_code=409,
            detail="That role name maps to a reserved system role identifier.",
        )
    if database_handler.role_exists(role_id):
        raise HTTPException(
            status_code=409,
            detail="A role with this identifier already exists on this instance.",
        )

    role = database_handler.create_role(
        role_id=role_id,
        role_name=role_name,
        privileges_ids=request.privileges_ids,
    )
    log_activity(
        activity_type="role_created",
        user_id=owner_user_id,
        title=f"Role {role.role_name} created",
        description=f"Custom role '{role.role_name}' was created.",
        metadata={"role_id": role.role_id, "privileges_ids": role.privileges_ids},
    )
    return {
        "status_code": 201,
        "message": "Role created successfully.",
        "role": _serialize_role(database_handler, role),
    }


@router.put("/roles/{role_id}", status_code=200)
async def update_role_route(role_id: str, request: RoleUpdateRequest):
    """Update a custom instance role."""
    owner_user_id = require_server_owner(request.auth_token)
    database_handler = require_component("database_handler")
    role_name = request.role_name.strip()
    if not role_name:
        raise HTTPException(status_code=422, detail="Role name cannot be empty.")

    if database_handler.is_system_role(role_id):
        raise HTTPException(
            status_code=403,
            detail="Built-in instance roles cannot be edited.",
        )

    valid_privileges = database_handler.get_privilege_ids()
    unknown_privileges = sorted(set(request.privileges_ids) - valid_privileges)
    if unknown_privileges:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown privileges: {', '.join(unknown_privileges)}",
        )

    updated_role = database_handler.update_role(
        role_id=role_id,
        role_name=role_name,
        privileges_ids=request.privileges_ids,
    )
    if updated_role is None:
        raise HTTPException(status_code=404, detail="Role not found.")

    log_activity(
        activity_type="role_updated",
        user_id=owner_user_id,
        title=f"Role {updated_role.role_name} updated",
        description=f"Custom role '{updated_role.role_name}' was updated.",
        metadata={
            "role_id": updated_role.role_id,
            "privileges_ids": updated_role.privileges_ids,
        },
    )
    return {
        "status_code": 200,
        "message": "Role updated successfully.",
        "role": _serialize_role(database_handler, updated_role),
    }


@router.delete("/roles/{role_id}", status_code=200)
async def delete_role_route(role_id: str, auth_token: str):
    """Delete a custom instance role."""
    owner_user_id = require_server_owner(auth_token)
    database_handler = require_component("database_handler")

    if database_handler.is_system_role(role_id):
        raise HTTPException(
            status_code=403,
            detail="Built-in instance roles cannot be deleted.",
        )

    if database_handler.count_users_for_role(role_id) > 0:
        raise HTTPException(
            status_code=409,
            detail="This role is still assigned to one or more users.",
        )

    if not database_handler.delete_role(role_id):
        raise HTTPException(status_code=404, detail="Role not found.")

    log_activity(
        activity_type="role_deleted",
        user_id=owner_user_id,
        title=f"Role {role_id} deleted",
        description=f"Custom role '{role_id}' was deleted.",
        metadata={"role_id": role_id},
    )
    return {"status_code": 200, "message": "Role deleted successfully."}


@router.put("/users/{target_user_id}/roles", status_code=200)
async def update_user_roles_route(target_user_id: str, request: UserRolesUpdateRequest):
    """Replace a user's assigned role ids on this instance."""
    owner_user_id = require_server_owner(request.auth_token)
    database_handler = require_component("database_handler")
    user_manager = require_component("user_manager")

    if not user_manager.check_user(user_id=target_user_id):
        raise HTTPException(status_code=404, detail="Target user not found.")

    normalized_role_ids = list(dict.fromkeys(request.roles_ids or [DEFAULT_ROLE_ID]))
    missing_role_ids = [
        role_id for role_id in normalized_role_ids if not database_handler.role_exists(role_id)
    ]
    if missing_role_ids:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown roles: {', '.join(sorted(missing_role_ids))}",
        )

    try:
        updated_user = user_manager.update_user_roles(
            target_user_id=target_user_id,
            role_ids=normalized_role_ids,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_activity(
        activity_type="user_roles_updated",
        user_id=owner_user_id,
        title=f"Roles updated for {updated_user.username}",
        description=f"Updated instance roles for user '{updated_user.username}'.",
        metadata={
            "target_user_id": target_user_id,
            "roles_ids": updated_user.roles_ids,
        },
    )
    return {
        "status_code": 200,
        "message": "User roles updated successfully.",
        "user": {
            "user_id": str(updated_user.user_id),
            "username": updated_user.username,
            "roles_ids": list(updated_user.roles_ids or []),
        },
    }
