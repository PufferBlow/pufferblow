"""User-facing notifications routes.

Lists the viewer's notifications (newest first), exposes the unread badge
count, and lets the viewer mark notifications read individually or in bulk.
Notification creation is server-internal — the route layer never accepts a
client-supplied notification body.
"""

from fastapi import APIRouter, exceptions

from pufferblow.api.dependencies import get_current_user
from pufferblow.core.bootstrap import api_initializer


router = APIRouter(prefix="/api/v1/notifications")

NOTIFICATIONS_DEFAULT_LIMIT = 50
NOTIFICATIONS_MAX_LIMIT = 100


@router.get("/", status_code=200)
async def list_notifications(
    auth_token: str,
    limit: int | None = NOTIFICATIONS_DEFAULT_LIMIT,
    unread_only: bool | None = False,
):
    """List the viewer's notifications, newest first.

    Args:
        auth_token: Viewer's auth token.
        limit: Max rows to return (default 50, max 100).
        unread_only: When true, skip notifications already marked read.
    """
    effective_limit = limit or NOTIFICATIONS_DEFAULT_LIMIT
    if effective_limit < 1 or effective_limit > NOTIFICATIONS_MAX_LIMIT:
        raise exceptions.HTTPException(
            detail=f"`limit` must be between 1 and {NOTIFICATIONS_MAX_LIMIT}.",
            status_code=400,
        )

    user_id = get_current_user(auth_token)

    rows = api_initializer.notifications_manager.list_for_user(
        user_id=user_id,
        limit=effective_limit,
        unread_only=bool(unread_only),
    )
    unread_count = api_initializer.notifications_manager.unread_count(
        user_id=user_id
    )

    return {
        "status_code": 200,
        "notifications": [row.to_dict() for row in rows],
        "unread_count": unread_count,
    }


@router.get("/unread_count", status_code=200)
async def notifications_unread_count(auth_token: str):
    """Cheap unread-badge count for the viewer."""
    user_id = get_current_user(auth_token)
    return {
        "status_code": 200,
        "unread_count": api_initializer.notifications_manager.unread_count(
            user_id=user_id
        ),
    }


@router.post("/{notification_id}/read", status_code=200)
async def mark_notification_read(auth_token: str, notification_id: str):
    """Mark a single notification read. Idempotent."""
    user_id = get_current_user(auth_token)
    changed = api_initializer.notifications_manager.mark_read(
        notification_id=notification_id, user_id=user_id
    )
    return {
        "status_code": 200,
        "already_read": not changed,
        "unread_count": api_initializer.notifications_manager.unread_count(
            user_id=user_id
        ),
    }


@router.post("/read-all", status_code=200)
async def mark_all_notifications_read(auth_token: str):
    """Mark every unread notification for the viewer as read."""
    user_id = get_current_user(auth_token)
    marked = api_initializer.notifications_manager.mark_all_read(user_id=user_id)
    return {
        "status_code": 200,
        "marked": marked,
        "unread_count": 0,
    }
