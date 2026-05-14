"""Notification recording + delivery surface.

v1.0 covers exactly one notification class: ``mention``. A message that
includes ``@<existing-username>`` produces one Notifications row per resolved
recipient (excluding the sender). The route layer is responsible for calling
:meth:`record_mentions_for_message` after a successful send.

Real-time delivery piggybacks on the existing WebSocket gateway: callers can
build the broadcast payload from :meth:`serialize_for_broadcast` and dispatch
through :class:`WebSocketsManager.broadcast_to_eligible_users` so the
recipient's open client(s) light up immediately.
"""

from __future__ import annotations

import re
import uuid

from loguru import logger

from pufferblow.api.database.database_handler import DatabaseHandler
from pufferblow.api.database.tables.notifications import Notifications


# Matches @-mentions in message bodies. The @ must be at the start of the
# string or preceded by whitespace; this rules out email addresses
# (user@example.com) and other inline @-suffixes (`#@`, `>@`, etc.) that
# aren't intended as mentions. Usernames are bounded to 32 chars and limited
# to ascii alnum + . _ - which matches the existing username constraints.
_MENTION_PATTERN = re.compile(r"(?:^|(?<=\s))@([A-Za-z0-9._-]{1,32})")


def extract_mention_usernames(content: str) -> list[str]:
    """Return distinct usernames mentioned in ``content``, preserving order.

    The matcher is conservative (32 chars max, lowercase ascii + . _ -). It
    intentionally does NOT resolve usernames against the DB — that's the
    manager's job.
    """
    if not content:
        return []
    seen: set[str] = set()
    ordered: list[str] = []
    for match in _MENTION_PATTERN.finditer(content):
        username = match.group(1)
        # Strip a trailing '.' that's almost certainly punctuation,
        # except when the username itself ends in a digit/letter dot pattern.
        cleaned = username.rstrip(".")
        if not cleaned:
            continue
        if cleaned in seen:
            continue
        seen.add(cleaned)
        ordered.append(cleaned)
    return ordered


class NotificationsManager:
    """Records and lists notifications. Stateless apart from its DB handler."""

    def __init__(self, database_handler: DatabaseHandler) -> None:
        """Initialize the instance."""
        self.database_handler = database_handler

    # --- Recording -------------------------------------------------------

    def record_mentions_for_message(
        self,
        *,
        content: str,
        sender_user_id: str,
        channel_id: str,
        message_id: str,
    ) -> list[Notifications]:
        """Resolve ``@username`` mentions in ``content`` and record one
        notification per recipient. The sender is never notified of their
        own mentions. Unknown usernames are silently skipped.

        Returns the rows that were persisted (in resolution order). The list
        is empty when the message contained no resolvable mentions.
        """
        usernames = extract_mention_usernames(content)
        if not usernames:
            return []

        rows: list[Notifications] = []
        seen_user_ids: set[str] = set()
        for username in usernames:
            try:
                user = self.database_handler.get_user(username=username)
            except Exception:
                logger.exception(
                    "Failed to resolve mention @{username} on channel "
                    "{channel_id}; skipping",
                    username=username,
                    channel_id=channel_id,
                )
                continue
            if user is None:
                continue
            recipient_id = str(user.user_id)
            if recipient_id == str(sender_user_id):
                continue
            if recipient_id in seen_user_ids:
                continue
            seen_user_ids.add(recipient_id)

            rows.append(
                Notifications(
                    notification_id=str(uuid.uuid4()),
                    user_id=user.user_id,
                    type="mention",
                    actor_user_id=sender_user_id,
                    channel_id=channel_id,
                    message_id=message_id,
                )
            )

        if rows:
            try:
                self.database_handler.create_notifications_bulk(rows)
            except Exception:
                logger.exception(
                    "Failed to persist {count} mention notifications for "
                    "message_id={message_id}",
                    count=len(rows),
                    message_id=message_id,
                )
                return []

        return rows

    # --- Read API --------------------------------------------------------

    def list_for_user(
        self,
        *,
        user_id: str,
        limit: int = 50,
        unread_only: bool = False,
    ) -> list[Notifications]:
        """Return the user's recent notifications, newest first."""
        return self.database_handler.list_notifications_for_user(
            user_id=user_id, limit=limit, unread_only=unread_only
        )

    def unread_count(self, *, user_id: str) -> int:
        """Cheap unread-badge count for the user."""
        return self.database_handler.count_unread_notifications_for_user(
            user_id=user_id
        )

    def mark_read(self, *, notification_id: str, user_id: str) -> bool:
        """Mark a single notification read; idempotent."""
        return self.database_handler.mark_notification_read(
            notification_id=notification_id, user_id=user_id
        )

    def mark_all_read(self, *, user_id: str) -> int:
        """Mark every unread notification for ``user_id`` as read."""
        return self.database_handler.mark_all_notifications_read(user_id=user_id)

    # --- Serialization ---------------------------------------------------

    @staticmethod
    def serialize_for_broadcast(notification: Notifications) -> dict:
        """Build the WebSocket payload for a freshly-created notification.

        Uses the ``type`` discriminator already established by the rest of
        the chat WS surface ('user_status_changed', 'user_joined', etc.) so
        the client's normalize_chat_websocket_message dispatch stays uniform.
        """
        return {
            "type": "notification_created",
            "notification": notification.to_dict(),
        }
