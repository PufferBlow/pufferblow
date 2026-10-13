"""Message operations, independent of any transport.

The WebSocket command handlers and the legacy HTTP routes both call this
service, so validation, authorization and persistence rules exist exactly once.
A method returns the value to send back to the caller plus the
:class:`DomainEvent` objects describing what changed. It never publishes: the
caller does that after the work has been committed.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from loguru import logger

from pufferblow.api.errors import ApiError, ErrorCode
from pufferblow.api.notifications.notifications_manager import mentions_everyone
from pufferblow.api.principals.authorizer import Authorizer
from pufferblow.api.principals.principal import Principal
from pufferblow.api.protocol.commands import MAX_EMOJI_LENGTH
from pufferblow.api.protocol.events import (
    MESSAGE_CREATED,
    MESSAGE_DELETED,
    MESSAGE_UPDATED,
    NOTIFICATION_CREATED,
    REACTION_ADDED,
    REACTION_REMOVED,
    DomainEvent,
    message_view,
)

#: Who may use ``@everyone``: the privilege the owner, administrators and moderators share (and
#: regular members lack), so it needs no new role data on instances that already exist.
EVERYONE_PRIVILEGE = "moderate_content"

#: ``(max_message_length, max_total_attachment_mb)``
MessagePolicy = Callable[[], tuple[int, int]]


@dataclass
class ServiceResult:
    value: dict[str, Any]
    events: list[DomainEvent] = field(default_factory=list)


def _iso(value: Any) -> str | None:
    if value is None or isinstance(value, str):
        return value
    return value.isoformat() if isinstance(value, datetime) else str(value)


def _public_reactions(summary: list[dict]) -> list[dict]:
    """Reaction summaries as broadcast to everyone: no per-viewer flag."""
    return [{k: v for k, v in entry.items() if k != "viewer_reacted"} for entry in summary]


class MessageService:
    def __init__(
        self,
        *,
        messages_manager,
        channels_manager,
        database_handler,
        user_manager,
        authorizer: Authorizer,
        policy: MessagePolicy,
        stickers_manager=None,
        notifications_manager=None,
    ) -> None:
        self._messages = messages_manager
        self._channels = channels_manager
        self._db = database_handler
        self._users = user_manager
        self._authz = authorizer
        self._policy = policy
        self._stickers = stickers_manager
        self._notifications = notifications_manager

    # ── helpers ────────────────────────────────────────────────

    def _require_user_principal(self, principal: Principal) -> None:
        # Reactions reference a user row directly (no bot-authored column, unlike
        # messages), so a bot cannot react yet — only post, edit and delete.
        if principal.is_bot:
            raise ApiError(ErrorCode.AUTH_PRIVILEGE_DENIED, user_message="Bots cannot react to messages yet.")

    def _bot_sender_profile(self, bot_id: str) -> dict[str, Any]:
        bot_row = self._db.get_bot(bot_id)
        return {
            "username": bot_row.name if bot_row else "Unknown Bot",
            "avatar_url": None,
            "banner_url": None,
            "status": "online",
            "roles_ids": [],
            "about": None,
            "last_seen": None,
            "created_at": None,
        }

    def _load_message(self, channel_id: str, message_id: str):
        row = self._db.get_message_by_id(message_id=message_id)
        if row is None or str(row.channel_id) != str(channel_id):
            raise ApiError(ErrorCode.MESSAGES_NOT_FOUND, details={"message_id": message_id})
        return row

    # ── create ─────────────────────────────────────────────────

    def create(
        self,
        principal: Principal,
        channel_id: str,
        content: str,
        *,
        sticker_ids: Sequence[str] = (),
        attachments: Sequence[dict] = (),
        sent_at: str | None = None,
        reply_to_message_id: str | None = None,
        forwarded_from_message_id: str | None = None,
    ) -> ServiceResult:
        max_length, _ = self._policy()
        if len(content) > max_length:
            raise ApiError(
                ErrorCode.MESSAGES_TOO_LONG,
                user_message=f"Message exceeds the instance limit of {max_length} characters.",
            )
        if not content.strip() and not attachments and not sticker_ids:
            raise ApiError(ErrorCode.MESSAGES_EMPTY, user_message="Either a message or attachments must be provided.")

        self._authz.require_send(principal, channel_id)

        if self._channels.get_channel_type(channel_id) == "voice":
            raise ApiError(ErrorCode.CHANNELS_VOICE_ONLY_NO_TEXT)

        # A reply can only answer a message in the same channel.
        if reply_to_message_id:
            self._load_message(channel_id, reply_to_message_id)

        attachment_objects = list(attachments) + self._resolve_stickers(sticker_ids)

        # ``sender_id`` on the row is always the owning user (bots have no row of
        # their own for that FK to target); ``sender_bot_id`` records which bot, if
        # any, actually sent it.
        bot_id = principal.id.split(":", 1)[1] if principal.is_bot else None
        message_obj = self._messages.send_message(
            channel_id=channel_id,
            user_id=principal.accountable_user_id,
            message=content,
            attachments=attachment_objects,
            sent_at=sent_at if sent_at and sent_at.strip() else None,
            sender_bot_id=bot_id,
            reply_to_message_id=reply_to_message_id or None,
            forwarded_from_message_id=forwarded_from_message_id or None,
        )

        sender = self._bot_sender_profile(bot_id) if principal.is_bot else self._users.user_profile(user_id=principal.id)
        message_dict = {
            "message_id": str(message_obj.message_id),
            "sender_user_id": principal.id,
            "channel_id": channel_id,
            "message": content,
            "hashed_message": message_obj.hashed_message,
            "username": sender["username"],
            "sender_avatar_url": sender.get("avatar_url"),
            "sender_banner_url": sender.get("banner_url"),
            "sender_status": sender.get("status", "offline"),
            "sender_roles": sender.get("roles_ids", []),
            "sender_about": sender.get("about"),
            "sender_last_seen": sender.get("last_seen"),
            "sender_created_at": sender.get("created_at"),
            "sent_at": _iso(message_obj.sent_at),
            "attachments": attachment_objects,
            "reply_to_message_id": reply_to_message_id or None,
            "reply_to": self._messages.reply_preview(reply_to_message_id) if reply_to_message_id else None,
            "forwarded_from_message_id": forwarded_from_message_id or None,
        }

        events = [
            DomainEvent(
                name=MESSAGE_CREATED,
                data=message_view(message_dict),
                channel_id=channel_id,
                legacy=message_dict,
            )
        ]
        events.extend(
            self._mention_events(
                content,
                principal.accountable_user_id,
                channel_id,
                str(message_obj.message_id),
                reply_to_message_id=reply_to_message_id or None,
                may_mention_everyone=principal.has(EVERYONE_PRIVILEGE),
            )
        )

        return ServiceResult(
            value={"message": message_view(message_dict), "legacy": message_dict},
            events=events,
        )

    def _resolve_stickers(self, sticker_ids: Sequence[str]) -> list[dict]:
        if not sticker_ids or self._stickers is None:
            return []
        resolved: list[dict] = []
        for sticker_id in sticker_ids:
            row = self._db.get_sticker_by_id(sticker_id)
            if row is None or not row.is_active:
                raise ApiError(
                    ErrorCode.STICKERS_NOT_AVAILABLE,
                    user_message=f"Sticker '{sticker_id}' isn't available.",
                )
            resolved.append(
                {
                    "url": row.sticker_url,
                    "filename": row.filename,
                    "type": "sticker",
                    "size": 0,
                    "sticker_id": row.sticker_id,
                    "display_name": row.display_name,
                    "alias": row.alias,
                }
            )
        return resolved

    def _mention_events(
        self,
        content: str,
        sender_id: str,
        channel_id: str,
        message_id: str,
        reply_to_message_id: str | None = None,
        may_mention_everyone: bool = False,
    ) -> list[DomainEvent]:
        """Mention and reply notifications are best effort: failing here must never fail the send."""
        if self._notifications is None:
            return []
        events: list[DomainEvent] = []
        try:
            notifications = self._notifications.record_mentions_for_message(
                content=content, sender_user_id=sender_id, channel_id=channel_id, message_id=message_id
            )
            # ``@everyone`` pings every member who can read the channel, but only when the sender may
            # moderate (owner, admins, moderators). From anyone else it is just text.
            if may_mention_everyone and mentions_everyone(content):
                notifications += self._notifications.record_everyone_for_message(
                    sender_user_id=sender_id,
                    channel_id=channel_id,
                    message_id=message_id,
                    recipient_ids=self._everyone_recipients(channel_id),
                    already_notified={str(n.user_id) for n in notifications},
                )
            if reply_to_message_id:
                notifications += self._notifications.record_reply_for_message(
                    sender_user_id=sender_id,
                    channel_id=channel_id,
                    message_id=message_id,
                    reply_to_message_id=reply_to_message_id,
                    already_notified={str(n.user_id) for n in notifications},
                )
            for notification in notifications:
                frame = self._notifications.serialize_for_broadcast(notification)
                events.append(
                    DomainEvent(
                        name=NOTIFICATION_CREATED,
                        data=frame,
                        target_user_id=str(notification.user_id),
                        legacy=frame,
                    )
                )
        except Exception:
            logger.exception(f"Mention-notification recording failed for message_id={message_id}")
        return events

    def _everyone_recipients(self, channel_id: str) -> list[str]:
        """Who ``@everyone`` reaches: every member, or in a private channel those allowed to read it."""
        everyone = [str(user_id) for user_id in self._db.get_users_id()]
        if not self._channels.is_private(channel_id=channel_id):
            return everyone
        return [uid for uid in everyone if "view_private_channels" in self._users.get_user_privileges(user_id=uid)]

    # ── edit ───────────────────────────────────────────────────

    def edit(self, principal: Principal, channel_id: str, message_id: str, content: str) -> ServiceResult:
        cleaned = (content or "").strip()
        if not cleaned:
            raise ApiError(ErrorCode.MESSAGES_EMPTY, user_message="Edited message cannot be empty.")
        max_length, _ = self._policy()
        if len(cleaned) > max_length:
            raise ApiError(
                ErrorCode.MESSAGES_TOO_LONG,
                user_message=f"Message exceeds the instance limit of {max_length} characters.",
            )

        self._authz.require_send(principal, channel_id, "edit messages")
        row = self._load_message(channel_id, message_id)
        self._authz.require_edit(principal, channel_id, str(row.sender_id), getattr(row, "sender_bot_id", None))

        result = self._messages.edit_message(
            message_id=message_id, editor_user_id=principal.accountable_user_id, new_body=cleaned
        )

        data = {
            "id": message_id,
            "channel_id": channel_id,
            "content": result["message"],
            "edit_count": result["edit_count"],
            "last_edited_at": result["last_edited_at"],
        }
        legacy = {
            "type": "message_edited",
            "message_id": message_id,
            "channel_id": channel_id,
            "message": result["message"],
            "edit_count": result["edit_count"],
            "last_edited_at": result["last_edited_at"],
        }
        return ServiceResult(
            value=data,
            events=[DomainEvent(name=MESSAGE_UPDATED, data=data, channel_id=channel_id, legacy=legacy)],
        )

    # ── delete ─────────────────────────────────────────────────

    def delete(self, principal: Principal, channel_id: str, message_id: str) -> ServiceResult:
        self._authz.require_channel_access(principal, channel_id)

        row = self._db.get_message_by_id(message_id=message_id)
        if row is None:
            # Already gone (for instance a retry after a lost acknowledgment): nothing to do.
            return ServiceResult(value={"id": message_id, "channel_id": channel_id, "deleted": False, "already_deleted": True})
        if str(row.channel_id) != str(channel_id):
            raise ApiError(ErrorCode.MESSAGES_NOT_FOUND, details={"message_id": message_id})

        self._authz.require_delete(principal, channel_id, str(row.sender_id))
        self._messages.delete_message(message_id=message_id, channel_id=channel_id)

        data = {"id": message_id, "channel_id": channel_id, "deleted_by": principal.id}
        return ServiceResult(
            value={"id": message_id, "channel_id": channel_id, "deleted": True, "already_deleted": False},
            # Older clients never had a delete frame, so none is invented for them.
            events=[DomainEvent(name=MESSAGE_DELETED, data=data, channel_id=channel_id, legacy=None)],
        )

    # ── reactions ──────────────────────────────────────────────

    def _normalise_emoji(self, emoji: str) -> str:
        value = (emoji or "").strip()
        if not value:
            raise ApiError(ErrorCode.VALIDATION_FIELD_REQUIRED, user_message="`emoji` cannot be empty.")
        if len(value) > MAX_EMOJI_LENGTH:
            raise ApiError(
                ErrorCode.VALIDATION_FIELD_RANGE,
                user_message=f"`emoji` exceeds the {MAX_EMOJI_LENGTH}-character maximum.",
            )
        if self._stickers is not None and value.startswith("sticker:"):
            from pufferblow.api.stickers.stickers_manager import StickersError

            try:
                value = self._stickers.validate_reaction_key(value)
            except StickersError as exc:
                raise ApiError(ErrorCode.STICKERS_NOT_AVAILABLE, user_message=str(exc), status=exc.status_code)
        return value

    def add_reaction(self, principal: Principal, channel_id: str, message_id: str, emoji: str) -> ServiceResult:
        self._require_user_principal(principal)
        value = self._normalise_emoji(emoji)

        self._authz.require_send(principal, channel_id, "react to messages")
        self._load_message(channel_id, message_id)

        newly_added = self._messages.add_reaction(message_id=message_id, user_id=principal.id, emoji=value)
        return self._reaction_result(principal, channel_id, message_id, value, REACTION_ADDED, "message_reaction_added", changed=newly_added)

    def remove_reaction(self, principal: Principal, channel_id: str, message_id: str, emoji: str) -> ServiceResult:
        self._require_user_principal(principal)
        value = (emoji or "").strip()
        if not value:
            raise ApiError(ErrorCode.VALIDATION_FIELD_REQUIRED, user_message="`emoji` cannot be empty.")

        self._authz.require_channel_access(principal, channel_id)
        self._load_message(channel_id, message_id)

        removed = self._messages.remove_reaction(message_id=message_id, user_id=principal.id, emoji=value)
        return self._reaction_result(principal, channel_id, message_id, value, REACTION_REMOVED, "message_reaction_removed", changed=removed)

    def _reaction_result(
        self, principal: Principal, channel_id: str, message_id: str, emoji: str,
        event_name: str, legacy_type: str, *, changed: bool,
    ) -> ServiceResult:
        summary = self._messages.get_reaction_summary(message_id=message_id, viewer_user_id=principal.id)
        public = _public_reactions(summary)
        value = {
            "message_id": message_id,
            "channel_id": channel_id,
            "emoji": emoji,
            "reactions": summary,
            "changed": changed,
        }
        if not changed:
            return ServiceResult(value=value)

        data = {"message_id": message_id, "channel_id": channel_id, "user_id": principal.id, "emoji": emoji, "reactions": public}
        legacy = {"type": legacy_type, **data}
        return ServiceResult(value=value, events=[DomainEvent(name=event_name, data=data, channel_id=channel_id, legacy=legacy)])

    # ── history (used for resync) ──────────────────────────────

    def recent(self, principal: Principal, channel_id: str, limit: int) -> list[dict]:
        self._authz.require_channel_access(principal, channel_id)
        rows = self._messages.load_messages(
            channel_id=channel_id, messages_per_page=limit, page=1, viewer_user_id=principal.id
        )
        if isinstance(rows, tuple):
            rows = rows[0]
        views = [message_view(row) for row in rows if isinstance(row, dict)]
        views.sort(key=lambda view: str(view["created_at"] or ""))
        return views
