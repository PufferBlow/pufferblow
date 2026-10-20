"""Central authorization for commands and subscriptions.

Every question the dispatcher or a service needs answered ("can this principal
send here?") goes through this one class, so a bot, a user, a WebSocket command
and an HTTP route are all judged by the same rules.
"""

from __future__ import annotations

from collections.abc import Callable

from loguru import logger

from pufferblow.api.errors import ApiError, ErrorCode
from pufferblow.api.principals.principal import Principal


class Authorizer:
    def __init__(self, user_manager, channels_manager) -> None:
        self._users = user_manager
        self._channels = channels_manager

    # ── queries ────────────────────────────────────────────────

    def channel_reader(self, channel_id: str) -> Callable[[Principal], bool]:
        """Who may read ``channel_id``, looked up once so many principals can be checked cheaply.

        A private channel admits holders of ``view_private_channels`` and the users on the
        channel's member list (``allowed_users``, managed by ``add_user``); a bot is judged
        by its owner, since the list holds real user ids. A missing channel admits no one.
        """
        channel = self._channels.get_channel(channel_id=channel_id)
        if channel is None:
            return lambda _principal: False
        if not channel.is_private:
            return lambda _principal: True
        members = {str(user_id) for user_id in channel.allowed_users or []}
        return lambda principal: principal.has("view_private_channels") or str(principal.accountable_user_id) in members

    def can_read_channel(self, principal: Principal, channel_id: str) -> bool:
        return self.channel_reader(channel_id)(principal)

    can_subscribe = can_read_channel

    # ── enforcement (raise ApiError) ──────────────────────────

    def require_privilege(self, principal: Principal, privilege: str) -> None:
        if not principal.has(privilege):
            logger.warning(
                "AUTHZ_PRIVILEGE_DENIED principal={principal} kind={kind} privilege={privilege}",
                principal=principal.id,
                kind=principal.kind,
                privilege=privilege,
            )
            raise ApiError(ErrorCode.AUTH_PRIVILEGE_DENIED, details={"privilege": privilege})

    def require_channel_access(self, principal: Principal, channel_id: str) -> None:
        """Missing and private-without-access look identical, so existence is not leaked."""
        if not self.can_read_channel(principal, channel_id):
            raise ApiError(ErrorCode.CHANNELS_NOT_FOUND, details={"channel_id": channel_id})

    def require_not_timed_out(self, principal: Principal, action: str) -> None:
        until = self._users.get_active_timeout_until(principal.accountable_user_id)
        if until is not None:
            raise ApiError(
                ErrorCode.MESSAGES_TIMED_OUT,
                user_message=f"You are timed out until {until.isoformat()} and cannot {action}.",
                details={"action": action, "until": until.isoformat()},
            )

    def require_send(self, principal: Principal, channel_id: str, action: str = "send messages") -> None:
        self.require_privilege(principal, "send_messages")
        self.require_channel_access(principal, channel_id)
        self.require_not_timed_out(principal, action)

    def require_edit(
        self, principal: Principal, channel_id: str, sender_id: str, sender_bot_id: str | None = None
    ) -> None:
        """Only the author may rewrite a message; moderators delete, they do not edit.

        ``sender_id`` is the row's ``sender_id`` column, which for a bot-authored
        message is the bot's owner (bots have no row of their own for that FK to
        target) — so this compares against ``accountable_user_id``, not ``id``,
        and a user's own id is unaffected since the two are the same for them.

        When ``sender_bot_id`` is set the bot is the author: only that bot may edit,
        not its owner, and a bot never edits a message a person wrote.
        """
        self.require_send(principal, channel_id, "edit messages")
        author_is_bot = bool(sender_bot_id)
        is_author = (
            principal.is_bot and author_is_bot and principal.id.split(":", 1)[1] == str(sender_bot_id)
            if (principal.is_bot or author_is_bot)
            else str(sender_id) == principal.accountable_user_id
        )
        if not is_author:
            raise ApiError(
                ErrorCode.AUTH_PRIVILEGE_DENIED,
                user_message="Only the original author can edit this message.",
            )

    def require_delete(
        self, principal: Principal, channel_id: str, sender_id: str, sender_bot_id: str | None = None
    ) -> None:
        """The author, or anyone holding ``delete_messages``.

        A bot's messages are stored under its owner (``sender_id``), so for a bot principal the
        owner's id is *not* proof of authorship: it may delete only what it posted itself
        (``sender_bot_id``), never a message its owner wrote. A user may delete their own, and
        their bots', messages.
        """
        self.require_channel_access(principal, channel_id)
        if principal.is_bot:
            is_author = bool(sender_bot_id) and principal.id.split(":", 1)[1] == str(sender_bot_id)
        else:
            is_author = str(sender_id) == principal.id
        if not is_author and not principal.has("delete_messages"):
            raise ApiError(
                ErrorCode.AUTH_PRIVILEGE_DENIED,
                user_message="You are not authorized to delete this message",
                details={"privilege": "delete_messages"},
            )
