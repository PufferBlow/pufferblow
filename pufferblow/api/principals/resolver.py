"""Turn validated credentials into a :class:`Principal`."""

from __future__ import annotations

from typing import Protocol

from pufferblow.api.errors import ApiError, ErrorCode
from pufferblow.api.principals.principal import Principal


class PrincipalResolver(Protocol):
    """Anything that can authenticate a credential string into a principal."""

    def resolve(self, credential: str) -> Principal:  # pragma: no cover - interface
        ...


class UserPrincipalResolver:
    """Authenticates a human session token using the existing user machinery."""

    def __init__(self, user_manager, auth_token_manager) -> None:
        self._users = user_manager
        self._tokens = auth_token_manager

    def resolve(self, credential: str) -> Principal:
        from pufferblow.api.utils.extract_user_id import extract_user_id

        if not credential or not self._tokens.check_auth_token_format(auth_token=credential):
            raise ApiError(ErrorCode.AUTH_INVALID_TOKEN)

        user_id = extract_user_id(auth_token=credential)
        if not self._users.check_user(user_id=user_id, auth_token=credential):
            raise ApiError(ErrorCode.AUTH_INVALID_TOKEN)

        refused = self._users.membership_error(user_id)
        if refused:
            raise ApiError(refused)

        if self._users.get_user_moderation_state(user_id=user_id).get("is_banned"):
            raise ApiError(ErrorCode.AUTH_USER_BANNED, details={"user_id": user_id})

        return Principal(
            id=str(user_id),
            kind="user",
            privileges=frozenset(self._users.get_user_privileges(user_id=user_id)),
            owner_user_id=str(user_id),
            auth_context="user_session",
        )

    def refresh(self, principal: Principal) -> Principal:
        """Re-read a user's effective privileges (after a role change)."""
        return Principal(
            id=principal.id,
            kind="user",
            privileges=frozenset(self._users.get_user_privileges(user_id=principal.id)),
            owner_user_id=principal.owner_user_id,
            auth_context=principal.auth_context,
        )


class BotPrincipalResolver:
    """Authenticates a bot token against hashed credentials.

    Foundation only: the ``/ws`` endpoint does not accept bot credentials in this
    phase. The resolver exists so authorization code is written against
    :class:`Principal` from day one and can be exercised in tests.
    """

    def __init__(self, bot_manager, user_manager) -> None:
        self._bots = bot_manager
        self._users = user_manager

    def resolve(self, credential: str) -> Principal:
        bot = self._bots.verify_token(credential)
        if bot is None:
            raise ApiError(ErrorCode.AUTH_INVALID_TOKEN)

        owner_privileges = set(self._users.get_user_privileges(user_id=bot.owner_user_id))
        scopes = frozenset(bot.scopes)
        return Principal(
            id=f"bot:{bot.bot_id}",
            kind="bot",
            # Never more than the owner holds, never more than the bot was granted.
            privileges=frozenset(owner_privileges & scopes),
            owner_user_id=str(bot.owner_user_id),
            scopes=scopes,
            auth_context="bot_token",
        )


class AnyPrincipalResolver:
    """Resolves either a user session token or a bot token into a Principal.

    Bot tokens are shaped ``pbb_<prefix>.<secret>`` (see ``bot_manager.TOKEN_MARKER``),
    which a user token never is, so routing on that prefix is unambiguous.
    """

    def __init__(self, user_resolver: UserPrincipalResolver, bot_resolver: BotPrincipalResolver) -> None:
        self._users = user_resolver
        self._bots = bot_resolver

    def resolve(self, credential: str) -> Principal:
        from pufferblow.api.bots.bot_manager import TOKEN_MARKER

        if credential and credential.startswith(f"{TOKEN_MARKER}_"):
            return self._bots.resolve(credential)
        return self._users.resolve(credential)
