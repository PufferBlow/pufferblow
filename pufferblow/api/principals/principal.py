"""The authenticated actor behind a command: a human user or a bot."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

PrincipalKind = Literal["user", "bot"]


@dataclass(frozen=True)
class Principal:
    """Who is acting. Always derived from validated credentials, never from a payload.

    ``privileges`` is the effective set after every restriction has been
    applied. For a bot that is the owner's privileges intersected with the
    bot's granted ``scopes``, so a bot can never do more than its owner or
    more than it was explicitly given.
    """

    id: str
    kind: PrincipalKind
    privileges: frozenset[str] = field(default_factory=frozenset)
    #: The human account responsible for the principal. For users this is the user itself.
    owner_user_id: str | None = None
    #: Capabilities granted to a bot. Empty for users (their privileges come from roles).
    scopes: frozenset[str] = field(default_factory=frozenset)
    #: How the principal authenticated, for logs ("user_session", "bot_token").
    auth_context: str = "user_session"

    @property
    def is_bot(self) -> bool:
        return self.kind == "bot"

    @property
    def accountable_user_id(self) -> str:
        """The user whose timeouts, bans and ownership checks apply."""
        return self.owner_user_id or self.id

    def has(self, privilege: str) -> bool:
        return privilege in self.privileges
