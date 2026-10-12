"""Central authorization for commands and subscriptions.

Every question the dispatcher or a service needs answered ("can this principal
send here?") goes through this one class, so a bot, a user, a WebSocket command
and an HTTP route are all judged by the same rules.
"""

from __future__ import annotations

from loguru import logger

from pufferblow.api.errors import ApiError, ErrorCode
from pufferblow.api.principals.principal import Principal


class Authorizer:
    def __init__(self, user_manager, channels_manager) -> None:
        self._users = user_manager
        self._channels = channels_manager

    # ── queries ────────────────────────────────────────────────

    def can_read_channel(self, principal: Principal, channel_id: str) -> bool:
        if not self._channels.check_channel(channel_id=channel_id):
            return False
        if self._channels.is_private(channel_id=channel_id):
            return principal.has("view_private_channels")
        return True

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

    def require_edit(self, principal: Principal, channel_id: str, sender_id: str) -> None:
        """Only the author may rewrite a message; moderators delete, they do not edit."""
        self.require_send(principal, channel_id, "edit messages")
        if str(sender_id) != principal.id:
            raise ApiError(
                ErrorCode.AUTH_PRIVILEGE_DENIED,
                user_message="Only the original author can edit this message.",
            )

    def require_delete(self, principal: Principal, channel_id: str, sender_id: str) -> None:
        self.require_channel_access(principal, channel_id)
        if str(sender_id) != principal.id and not principal.has("delete_messages"):
            raise ApiError(
                ErrorCode.AUTH_PRIVILEGE_DENIED,
                user_message="You are not authorized to delete this message",
                details={"privilege": "delete_messages"},
            )
