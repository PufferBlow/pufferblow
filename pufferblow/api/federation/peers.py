"""What this instance has decided about the instances it federates with, and the checks that enforce it.

Three ideas:

* A **mode** frames everything: ``open`` (anyone may federate unless blocked), ``allowlist`` (only instances
  an admin approved) and ``closed`` (nobody).
* Each **peer** has a **status**: ``federating``, ``pending`` (seen, waiting for an admin), ``limited`` or
  ``blocked``.
* Each peer has three **policy** switches: ``media`` (whether its pictures and files are shown here),
  ``voice`` (whether its people may join voice rooms here) and ``discover`` (whether its public spaces are
  listed for members). A switch follows the status unless an admin set it by hand.

Only ``media`` is enforced today (attachments from a peer with it off are dropped on the way in). ``voice``
and ``discover`` are recorded and offered to the parts that will use them; nothing here pretends otherwise.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

STATUSES = ("federating", "pending", "limited", "blocked")
MODES = ("open", "allowlist", "closed")
POLICY_KEYS = ("media", "voice", "discover")
DEFAULT_MODE = "open"

#: What each status means for the switches, until an admin changes one.
STATUS_DEFAULTS: dict[str, dict[str, bool]] = {
    "federating": {"media": True, "voice": True, "discover": True},
    "limited": {"media": False, "voice": True, "discover": False},
    "pending": {"media": False, "voice": False, "discover": False},
    "blocked": {"media": False, "voice": False, "discover": False},
}

_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:\d{1,5})?$")


class PeerError(ValueError):
    """A peer, status, mode or switch that is not valid. ``field`` names the offender."""

    def __init__(self, message: str, field: str = "host") -> None:
        super().__init__(message)
        self.field = field


class FederationRefused(Exception):
    """Federation with this host is not allowed right now. ``reason`` is ``closed``, ``blocked``, ``pending`` or ``not_approved``."""

    def __init__(self, host: str, reason: str) -> None:
        super().__init__(f"federation with {host} refused: {reason}")
        self.host = host
        self.reason = reason


def normalize_host(value: str) -> str:
    """The host (and port) of an address, lower-cased: accepts ``Host.Example``, ``host:8080`` and full URLs.

    Raises :class:`PeerError` for anything that is not a plain internet host name, so what is stored and
    compared can never carry a path, credentials or whitespace.
    """
    text = (value or "").strip().lower()
    if not text:
        raise PeerError("A host is required.")
    if "://" in text:
        parts = urlsplit(text)
        if parts.username or parts.password:
            raise PeerError("A host cannot include credentials.")
        text = parts.netloc
    elif "/" in text or "@" in text or "?" in text or "#" in text:
        raise PeerError("Give a host like mesh.garden, not a path or an account.")
    text = text.rstrip(".")
    if not _HOST.match(text):
        raise PeerError(f"'{value.strip()[:80]}' is not a valid host.")
    port = text.rsplit(":", 1)[1] if ":" in text else None
    if port is not None and not (1 <= int(port) <= 65535):
        raise PeerError("The port is out of range.")
    return text


def host_of(uri: str) -> str:
    """The host of an actor or object URI, or "" when it has none (a ``urn:`` id, say)."""
    try:
        return urlsplit(uri).netloc.lower().rstrip(".")
    except ValueError:
        return ""


def effective_policy(status: str, overrides: dict[str, Any] | None) -> dict[str, bool]:
    """The three switches for a peer: its status's defaults, with whatever an admin set by hand on top."""
    policy = dict(STATUS_DEFAULTS.get(status, STATUS_DEFAULTS["pending"]))
    if status in ("blocked", "pending"):
        return policy  # nothing is shared with an instance that is not federating, whatever was set before
    for key in POLICY_KEYS:
        if isinstance((overrides or {}).get(key), bool):
            policy[key] = overrides[key]
    return policy


def validate_policy(changes: Any) -> dict[str, bool]:
    """A partial update of the switches, or a :class:`PeerError` naming the bad key."""
    if not isinstance(changes, dict) or not changes:
        raise PeerError("Send at least one of media, voice, discover.", "policy")
    clean: dict[str, bool] = {}
    for key, value in changes.items():
        if key not in POLICY_KEYS:
            raise PeerError(f"{key} is not a policy switch; use any of {list(POLICY_KEYS)}.", key)
        if not isinstance(value, bool):
            raise PeerError(f"{key} must be true or false.", key)
        clean[key] = value
    return clean


@dataclass(frozen=True)
class Decision:
    allowed: bool
    #: Why not: ``closed``, ``blocked``, ``pending`` or ``not_approved``. Empty when allowed.
    reason: str = ""


ALLOW = Decision(True)


class PeerPolicy:
    """Answers "may this host federate with us?" and keeps what it learns about each host.

    ``database`` is the database handler (it must have the federation mixin); ``is_local`` says whether a
    host is this instance itself, which is never policed.
    """

    def __init__(self, database: Any, is_local: Callable[[str], bool] | None = None) -> None:
        self.database = database
        self._is_local = is_local or (lambda host: False)

    @property
    def available(self) -> bool:
        """False for a database handler that has no federation tables (some tests build one by hand)."""
        return hasattr(self.database, "get_federation_mode")

    def mode(self) -> str:
        return self.database.get_federation_mode()

    def decide_inbound(self, host: str) -> Decision:
        """May an activity from ``host`` be processed? Registers hosts it has not seen before."""
        if not self.available or not host or self._is_local(host):
            return ALLOW
        mode = self.mode()
        if mode == "closed":
            return Decision(False, "closed")
        peer = self.database.get_peer(host)
        if peer is None:
            if mode == "open":
                self.database.upsert_peer(host, "federating")
                return ALLOW
            self.database.upsert_peer(host, "pending")  # an admin will see it and decide
            return Decision(False, "pending")
        if peer["status"] == "blocked":
            return Decision(False, "blocked")
        if peer["status"] == "pending":
            if mode == "open":
                self.database.set_peer_status(host, "federating")  # open means open: no approval to wait for
            else:
                return Decision(False, "pending")
        self.database.touch_peer_activity(host)
        return ALLOW

    def decide_outbound(self, host: str) -> Decision:
        """May we send something to ``host``? A host we have never dealt with is noted for the admin."""
        if not self.available or not host or self._is_local(host):
            return ALLOW
        mode = self.mode()
        if mode == "closed":
            return Decision(False, "closed")
        peer = self.database.get_peer(host)
        if peer is None:
            if mode == "open":
                self.database.upsert_peer(host, "federating")
                return ALLOW
            self.database.upsert_peer(host, "pending")
            return Decision(False, "not_approved")
        if peer["status"] == "blocked":
            return Decision(False, "blocked")
        if peer["status"] == "pending" and mode != "open":
            return Decision(False, "not_approved")
        return ALLOW

    def policy_for(self, host: str) -> dict[str, bool]:
        """The switches for ``host``. A host not known (or a local one) gets the most open set."""
        if not self.available or not host or self._is_local(host):
            return dict(STATUS_DEFAULTS["federating"])
        peer = self.database.get_peer(host)
        return dict(peer["policy"]) if peer else dict(STATUS_DEFAULTS["federating"])

    def record_delivery(self, host: str, ok: bool, latency_ms: int | None = None) -> None:
        if self.available and host and not self._is_local(host):
            self.database.record_peer_delivery(host, ok, latency_ms)
