"""Bot identities and credentials (foundation).

Nothing here is exposed over HTTP or WebSocket yet. The manager exists so the
authorization layer can already reason about bot principals and so the storage
rules (hash only, shown once, revocable, never an admin) are fixed before any
public surface is built on top.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from pufferblow.api.database.tables.bots import Bots

#: The only capabilities a bot can ever be granted. Administrative privileges are deliberately absent.
ALLOWED_BOT_SCOPES: frozenset[str] = frozenset({"send_messages", "view_private_channels"})

TOKEN_MARKER = "pbb"
PREFIX_LENGTH = 10


@dataclass(frozen=True)
class BotIdentity:
    bot_id: str
    owner_user_id: str
    name: str
    scopes: tuple[str, ...]


@dataclass(frozen=True)
class CreatedBot:
    """Returned once, at creation. ``token`` is not recoverable afterwards."""

    identity: BotIdentity
    token: str


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


class BotManager:
    def __init__(self, database_handler) -> None:
        self._db = database_handler

    def create_bot(self, owner_user_id: str, name: str, scopes: list[str] | None = None) -> CreatedBot:
        name = (name or "").strip()
        if not name or len(name) > 64:
            raise ValueError("A bot needs a name of 1 to 64 characters.")

        granted = sorted(set(scopes or []))
        unknown = [scope for scope in granted if scope not in ALLOWED_BOT_SCOPES]
        if unknown:
            raise ValueError(f"Scopes not available to bots: {', '.join(unknown)}")

        # The token carries 256 bits of randomness, so a fast hash is enough; the
        # prefix is only a lookup key and reveals nothing useful on its own.
        prefix = secrets.token_hex(PREFIX_LENGTH // 2)
        secret = secrets.token_urlsafe(32)
        bot = Bots(
            bot_id=str(uuid.uuid4()),
            owner_user_id=str(owner_user_id),
            name=name,
            enabled=True,
            scopes=granted,
            token_prefix=prefix,
            token_hash=_hash(secret),
            created_at=datetime.now(timezone.utc),
        )
        self._db.insert_bot(bot)

        return CreatedBot(
            identity=BotIdentity(bot.bot_id, bot.owner_user_id, bot.name, tuple(granted)),
            token=f"{TOKEN_MARKER}_{prefix}.{secret}",
        )

    def verify_token(self, token: str) -> BotIdentity | None:
        """Return the bot a token belongs to, or None. Disabled and revoked bots never verify."""
        try:
            marker, rest = token.split("_", 1)
            prefix, secret = rest.split(".", 1)
        except (AttributeError, ValueError):
            return None
        if marker != TOKEN_MARKER or not prefix or not secret:
            return None

        row = self._db.get_bot_by_prefix(prefix)
        if row is None:
            # Spend the same work as a hit so timing does not reveal valid prefixes.
            hmac.compare_digest(_hash(secret), "0" * 64)
            return None

        if not hmac.compare_digest(_hash(secret), row.token_hash):
            return None
        if not row.enabled or row.revoked_at is not None:
            return None

        return BotIdentity(row.bot_id, row.owner_user_id, row.name, tuple(row.scopes or ()))

    def revoke(self, bot_id: str) -> bool:
        return self._db.revoke_bot(bot_id)
