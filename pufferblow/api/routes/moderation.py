"""Moderation and reporting routes."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, exceptions

from pufferblow.api.database.tables.activity_audit import ActivityAudit
from pufferblow.api.dependencies import (
    check_channel_access,
    get_current_user,
    require_privilege,
)
from pufferblow.api.schemas import (
    MessageReportRequest,
    UserBanRequest,
    UserReportRequest,
    UserTimeoutRequest,
)
from pufferblow.core.bootstrap import api_initializer

router = APIRouter(prefix="/api/v1/moderation")


def _create_audit_entry(
    *,
    actor_user_id: str,
    activity_type: str,
    title: str,
    description: str,
    metadata: dict,
) -> None:
    api_initializer.database_handler.create_activity_audit_entry(
        ActivityAudit(
            activity_id=str(uuid.uuid4()),
            activity_type=activity_type,
            user_id=str(actor_user_id),
            title=title,
            description=description,
            metadata_json=json.dumps(metadata),
        )
    )


def _ensure_target_user_is_actionable(actor_user_id: str, target_user_id: str) -> None:
    if str(actor_user_id) == str(target_user_id):
        raise exceptions.HTTPException(
            status_code=400,
            detail="You cannot perform moderation actions on your own account.",
        )

    if not api_initializer.user_manager.check_user(user_id=target_user_id):
        raise exceptions.HTTPException(status_code=404, detail="Target user not found.")

    if api_initializer.user_manager.is_server_owner(user_id=target_user_id):
        raise exceptions.HTTPException(
            status_code=403,
            detail="The server owner cannot be moderated through this route.",
        )


@router.post("/reports/messages", status_code=201)
async def report_messages_route(request: MessageReportRequest) -> dict:
    """Submit a report for one or more messages."""
    reporter_user_id = get_current_user(request.auth_token)

    validated_messages: list[str] = []
    channels: set[str] = set()

    for message_id in request.message_ids:
        message_metadata = api_initializer.database_handler.get_message_metadata(message_id)
        if message_metadata is None:
            raise exceptions.HTTPException(
                status_code=404,
                detail=f"Reported message '{message_id}' could not be found.",
            )

        if message_metadata.channel_id:
            check_channel_access(
                user_id=reporter_user_id,
                channel_id=str(message_metadata.channel_id),
            )
            channels.add(str(message_metadata.channel_id))

        validated_messages.append(message_id)

    _create_audit_entry(
        actor_user_id=reporter_user_id,
        activity_type="message_report_submitted",
        title="Message report submitted",
        description=f"Reported {len(validated_messages)} message(s) for moderator review.",
        metadata={
            "message_ids": validated_messages,
            "channel_ids": sorted(channels),
            "category": request.category,
            "description": request.description,
            "reporter_user_id": reporter_user_id,
            "submitted_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    return {
        "status_code": 201,
        "message": "Message report submitted successfully.",
        "reported_count": len(validated_messages),
    }


@router.post("/reports/users", status_code=201)
async def report_user_route(request: UserReportRequest) -> dict:
    """Submit a report for a user."""
    reporter_user_id = get_current_user(request.auth_token)

    if not api_initializer.user_manager.check_user(user_id=request.target_user_id):
        raise exceptions.HTTPException(status_code=404, detail="Target user not found.")

    target_user = api_initializer.user_manager.user_profile(user_id=request.target_user_id)

    _create_audit_entry(
        actor_user_id=reporter_user_id,
        activity_type="user_report_submitted",
        title=f"User report submitted for {target_user.get('username', request.target_user_id)}",
        description="A user profile was reported for moderator review.",
        metadata={
            "target_user_id": request.target_user_id,
            "target_username": target_user.get("username"),
            "category": request.category,
            "description": request.description,
            "reporter_user_id": reporter_user_id,
            "submitted_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    return {
        "status_code": 201,
        "message": "User report submitted successfully.",
        "target_user_id": request.target_user_id,
    }


@router.post("/users/{target_user_id}/ban", status_code=201)
async def ban_user_route(target_user_id: str, request: UserBanRequest) -> dict:
    """Ban a user from the current home instance."""
    actor_user_id = require_privilege(request.auth_token, "ban_users")
    _ensure_target_user_is_actionable(actor_user_id, target_user_id)

    target_user = api_initializer.user_manager.user_profile(user_id=target_user_id)

    _create_audit_entry(
        actor_user_id=actor_user_id,
        activity_type="user_banned",
        title=f"User {target_user.get('username', target_user_id)} banned",
        description="A moderator banned this user from the current home instance.",
        metadata={
            "target_user_id": target_user_id,
            "target_username": target_user.get("username"),
            "reason": request.reason,
            "banned_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    return {
        "status_code": 201,
        "message": f"User '{target_user.get('username', target_user_id)}' has been banned.",
        "target_user_id": target_user_id,
    }


@router.delete("/users/{target_user_id}/ban", status_code=200)
async def unban_user_route(target_user_id: str, auth_token: str) -> dict:
    """Lift an existing user ban."""
    actor_user_id = require_privilege(auth_token, "ban_users")

    if not api_initializer.user_manager.check_user(user_id=target_user_id):
        raise exceptions.HTTPException(status_code=404, detail="Target user not found.")

    target_user = api_initializer.user_manager.user_profile(user_id=target_user_id)

    _create_audit_entry(
        actor_user_id=actor_user_id,
        activity_type="user_unbanned",
        title=f"User {target_user.get('username', target_user_id)} unbanned",
        description="A moderator lifted this user's ban.",
        metadata={
            "target_user_id": target_user_id,
            "target_username": target_user.get("username"),
            "unbanned_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    return {
        "status_code": 200,
        "message": f"User '{target_user.get('username', target_user_id)}' has been unbanned.",
        "target_user_id": target_user_id,
    }


@router.post("/users/{target_user_id}/timeout", status_code=201)
async def timeout_user_route(target_user_id: str, request: UserTimeoutRequest) -> dict:
    """Apply a temporary messaging/voice timeout to a user."""
    actor_user_id = require_privilege(request.auth_token, "mute_users")
    _ensure_target_user_is_actionable(actor_user_id, target_user_id)

    target_user = api_initializer.user_manager.user_profile(user_id=target_user_id)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=request.duration_minutes)

    _create_audit_entry(
        actor_user_id=actor_user_id,
        activity_type="user_timed_out",
        title=f"User {target_user.get('username', target_user_id)} timed out",
        description="A moderator temporarily restricted this user's ability to speak and send messages.",
        metadata={
            "target_user_id": target_user_id,
            "target_username": target_user.get("username"),
            "duration_minutes": request.duration_minutes,
            "expires_at": expires_at.isoformat(),
            "reason": request.reason,
            "timed_out_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    return {
        "status_code": 201,
        "message": f"User '{target_user.get('username', target_user_id)}' has been timed out.",
        "target_user_id": target_user_id,
        "expires_at": expires_at.isoformat(),
    }


@router.delete("/users/{target_user_id}/timeout", status_code=200)
async def clear_user_timeout_route(target_user_id: str, auth_token: str) -> dict:
    """Clear an active user timeout."""
    actor_user_id = require_privilege(auth_token, "mute_users")

    if not api_initializer.user_manager.check_user(user_id=target_user_id):
        raise exceptions.HTTPException(status_code=404, detail="Target user not found.")

    target_user = api_initializer.user_manager.user_profile(user_id=target_user_id)

    _create_audit_entry(
        actor_user_id=actor_user_id,
        activity_type="user_timeout_cleared",
        title=f"Timeout cleared for {target_user.get('username', target_user_id)}",
        description="A moderator removed this user's timeout.",
        metadata={
            "target_user_id": target_user_id,
            "target_username": target_user.get("username"),
            "cleared_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    return {
        "status_code": 200,
        "message": f"Timeout cleared for '{target_user.get('username', target_user_id)}'.",
        "target_user_id": target_user_id,
    }
