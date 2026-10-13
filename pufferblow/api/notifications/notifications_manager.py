"""Notification recording + delivery surface.

v1.0 covers two notification classes: ``mention`` and ``reply``. A message that
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


#: Mentions that are not people. ``@everyone`` pings the whole channel and is only honoured for
#: members who may moderate (see :func:`mentions_everyone`); nobody can sign up with this name.
EVERYONE_MENTION = "everyone"
RESERVED_MENTION_NAMES = frozenset({EVERYONE_MENTION})


def is_reserved_username(username: str | None) -> bool:
    """Whether ``username`` is a name only mentions may use (compared ignoring case and edges)."""
    return (username or "").strip().lower() in RESERVED_MENTION_NAMES


def mentions_everyone(content: str) -> bool:
    """Whether ``content`` contains ``@everyone`` as its own word."""
    return EVERYONE_MENTION in {u.lower() for u in extract_mention_usernames(content, include_reserved=True)}


def extract_mention_usernames(content: str, *, include_reserved: bool = False) -> list[str]:
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
        if cleaned.lower() in RESERVED_MENTION_NAMES and not include_reserved:
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

    def _user_id_value(self, user_id):
        """A user id in the form the notifications table binds: a string on SQLite, a UUID elsewhere."""
        if self.database_handler._is_sqlite():
            return str(user_id)
        return user_id if isinstance(user_id, uuid.UUID) else uuid.UUID(str(user_id))

    def record_everyone_for_message(
        self,
        *,
        sender_user_id: str,
        channel_id: str,
        message_id: str,
        recipient_ids: list[str],
        already_notified: set[str] | None = None,
    ) -> list[Notifications]:
        """One ``mention`` notification for each of ``recipient_ids`` ( the people who can read the
        channel), except the sender, anyone already pinged by name for this message, and anyone who
        muted the channel. The caller decides who may use ``@everyone`` and who can read the channel.
        """
        try:
            muted = self.database_handler.muted_user_ids_for_channel(channel_id=channel_id)
        except Exception:
            logger.exception(f"Failed to read mute prefs for channel={channel_id}; notifying everyone")
            muted = set()

        skip = {str(sender_user_id), *(already_notified or set()), *muted}
        rows = [
            Notifications(
                notification_id=str(uuid.uuid4()),
                user_id=self._user_id_value(recipient),
                type="mention",
                actor_user_id=self._user_id_value(sender_user_id),
                channel_id=channel_id,
                message_id=message_id,
            )
            for recipient in dict.fromkeys(str(r) for r in recipient_ids)
            if recipient not in skip
        ]
        if not rows:
            return []
        try:
            self.database_handler.create_notifications_bulk(rows)
        except Exception:
            logger.exception(f"Failed to persist {len(rows)} @everyone notifications for message_id={message_id}")
            return []
        return rows

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

            # Per-channel mute. We honor the recipient's explicit
            # "mute #channel" choice by not recording the notification
            # row at all — that way the badge count stays correct, the
            # in-app notification list doesn't grow, AND no WS
            # notification_created event will fire from the caller (the
            # rows list filters out muted recipients before broadcast).
            #
            # Mentions in muted channels are intentional: a user who
            # muted #general doesn't want pings every time someone says
            # their handle there. Matches Discord and Slack semantics.
            try:
                if self.database_handler.is_channel_muted_for_user(
                    user_id=recipient_id, channel_id=channel_id
                ):
                    continue
            except Exception:
                # Mute lookup must never block notification delivery.
                # Fall through to the default (notify).
                logger.exception(
                    "Failed to read mute pref for user={user_id} "
                    "channel={channel_id}; defaulting to notify",
                    user_id=recipient_id,
                    channel_id=channel_id,
                )

            rows.append(
                Notifications(
                    notification_id=str(uuid.uuid4()),
                    user_id=self._user_id_value(user.user_id),
                    type="mention",
                    actor_user_id=self._user_id_value(sender_user_id),
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

    def record_reply_for_message(
        self,
        *,
        sender_user_id: str,
        channel_id: str,
        message_id: str,
        reply_to_message_id: str,
        already_notified: set[str] | None = None,
    ) -> list[Notifications]:
        """Tell the author of the message being replied to that someone answered them.

        One ``reply`` notification for the original author, unless that is the sender, they
        muted the channel, or ``already_notified`` says they are getting a mention for this very
        message (one ping per message is enough). Returns the rows persisted, at most one.
        """
        try:
            original = self.database_handler.get_message_by_id(message_id=reply_to_message_id)
        except Exception:
            logger.exception(f"Failed to look up the replied-to message {reply_to_message_id}; skipping")
            return []
        if original is None or original.sender_id is None:
            return []

        recipient_id = str(original.sender_id)
        if recipient_id == str(sender_user_id) or recipient_id in (already_notified or set()):
            return []

        try:
            if self.database_handler.is_channel_muted_for_user(user_id=recipient_id, channel_id=channel_id):
                return []
        except Exception:
            # Mute lookup must never block delivery; default to notifying.
            logger.exception(f"Failed to read mute pref for user={recipient_id} channel={channel_id}")

        row = Notifications(
            notification_id=str(uuid.uuid4()),
            user_id=self._user_id_value(original.sender_id),
            type="reply",
            actor_user_id=self._user_id_value(sender_user_id),
            channel_id=channel_id,
            message_id=message_id,
        )
        try:
            self.database_handler.create_notifications_bulk([row])
        except Exception:
            logger.exception(f"Failed to persist the reply notification for message_id={message_id}")
            return []
        return [row]

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
