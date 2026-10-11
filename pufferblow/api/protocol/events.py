"""Event names and the transport-independent message view used in payloads."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

MESSAGE_CREATED = "message.created"
MESSAGE_UPDATED = "message.updated"
MESSAGE_DELETED = "message.deleted"
REACTION_ADDED = "reaction.added"
REACTION_REMOVED = "reaction.removed"
CHANNEL_UPDATED = "channel.updated"
PRESENCE_CHANGED = "presence.changed"
NOTIFICATION_CREATED = "notification.created"

EVENT_NAMES = (
    MESSAGE_CREATED,
    MESSAGE_UPDATED,
    MESSAGE_DELETED,
    REACTION_ADDED,
    REACTION_REMOVED,
    CHANNEL_UPDATED,
    PRESENCE_CHANGED,
    NOTIFICATION_CREATED,
)


@dataclass(frozen=True)
class DomainEvent:
    """Something that has already been committed.

    Services return these; they never send anything themselves. The publisher
    turns each one into a v1 ``event`` envelope for v1 sessions and into the
    ``legacy`` frame (the pre-protocol shape) for older clients.
    """

    name: str
    data: dict[str, Any]
    #: Channel the event belongs to; subscription and authorization are checked against it.
    channel_id: str | None = None
    #: Deliver to this user's connections only (e.g. notifications) instead of a channel.
    target_user_id: str | None = None
    #: The frame older clients understand, or None when there never was one.
    legacy: dict[str, Any] | None = None
    #: Connection session that caused the event; its own echo is not suppressed, only labelled.
    origin_command_id: str | None = field(default=None, compare=False)


def message_view(raw: dict[str, Any]) -> dict[str, Any]:
    """Map a hydrated/legacy message dict to the v1 message object.

    Accepts both shapes the backend produces: the live/send shape (``username``)
    and the hydrated database shape (``sender_username``).
    """
    return {
        "id": str(raw.get("message_id", "")),
        "channel_id": raw.get("channel_id"),
        "author_id": str(raw.get("sender_user_id") or raw.get("sender_id") or ""),
        "author_name": raw.get("username") or raw.get("sender_username") or "",
        "author_avatar_url": raw.get("sender_avatar_url"),
        "content": raw.get("message") or "",
        "attachments": raw.get("attachments") or [],
        "reactions": [
            {"emoji": r.get("emoji"), "count": r.get("count", len(r.get("user_ids") or [])), "user_ids": r.get("user_ids") or []}
            for r in (raw.get("reactions") or [])
            if isinstance(r, dict)
        ],
        "created_at": raw.get("sent_at"),
        "edit_count": raw.get("edit_count") or 0,
        "last_edited_at": raw.get("last_edited_at"),
    }
