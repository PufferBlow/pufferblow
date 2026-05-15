"""User-facing notifications routes.

Lists the viewer's notifications (newest first), exposes the unread badge
count, and lets the viewer mark notifications read individually or in bulk.
Notification creation is server-internal — the route layer never accepts a
client-supplied notification body.

Per-channel mute prefs live under ``/preferences`` and are honored by the
notification recording path so muted channels never produce notification
rows in the first place — the badge stays accurate, the WS broadcast is
skipped, and the in-app notification list isn't polluted.
"""

from fastapi import APIRouter, Body, exceptions

from pufferblow.api.dependencies import check_channel_access, get_current_user
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


# ─────────────────────────────────────────────
# Per-channel preferences
# ─────────────────────────────────────────────


@router.get("/preferences", status_code=200)
async def list_notification_preferences(auth_token: str):
    """Return every persisted notification preference for the viewer.

    Only deviations from the default (notify normally) are stored, so the
    returned list is small in practice. Channels not present in the list
    behave as default — no client-side state needed beyond rendering the
    ones that are explicitly set.
    """
    user_id = get_current_user(auth_token)
    rows = api_initializer.database_handler.list_notification_preferences_for_user(
        user_id=user_id
    )
    return {
        "status_code": 200,
        "preferences": [row.to_dict() for row in rows],
    }


@router.put("/preferences/{channel_id}", status_code=200)
async def upsert_notification_preference(
    channel_id: str,
    auth_token: str,
    muted: bool = Body(default=False, embed=True),
    mention_only: bool = Body(default=False, embed=True),
):
    """Set the viewer's notification preference for a channel.

    Body:
        muted: when true, suppress all notifications for this channel.
        mention_only: reserved for v1.1 — currently affects nothing
            because the only notification class emitted in v1.0 is
            ``mention``. Stored for forward compatibility so the wire
            surface stays stable.
    """
    user_id = get_current_user(auth_token)
    # Re-use the same channel-access guard the rest of the channel routes
    # use — non-members shouldn't even be able to read whether a channel
    # exists, much less mute it.
    check_channel_access(user_id=user_id, channel_id=channel_id)
    row = api_initializer.database_handler.upsert_notification_preference(
        user_id=user_id,
        channel_id=channel_id,
        muted=bool(muted),
        mention_only=bool(mention_only),
    )
    return {
        "status_code": 200,
        "preference": row.to_dict(),
    }


@router.delete("/preferences/{channel_id}", status_code=200)
async def reset_notification_preference(channel_id: str, auth_token: str):
    """Reset a channel's preferences to defaults (delete the row).

    Idempotent — returns ``existed=False`` when no row was stored.
    """
    user_id = get_current_user(auth_token)
    check_channel_access(user_id=user_id, channel_id=channel_id)
    existed = api_initializer.database_handler.delete_notification_preference(
        user_id=user_id, channel_id=channel_id
    )
    return {
        "status_code": 200,
        "existed": existed,
    }
