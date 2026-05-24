"""Instance stickers — business logic over ``server_stickers``.

The route layer (``api/routes/stickers.py``) is a thin wrapper over
this class; lifecycle, validation, and caching live here so they're
testable independently of the FastAPI plumbing.

Why a separate manager when ``DatabaseHandler`` already has the CRUD
verbs? Two reasons:

  1. Upload-and-catalog is a multi-step operation (storage upload →
     URL → DB insert). That doesn't belong in either ``StorageManager``
     or ``DatabaseHandler``; both are accessed by lots of unrelated
     code. A focused manager keeps the orchestration in one place.

  2. The picker hits ``list_active`` on every chat open. That call
     needs caching — memcache + in-process LRU layered via
     ``get_cache``. Putting the cache write/invalidate around the
     CRUD verbs in ``DatabaseHandler`` would bleed cache concerns
     across hundreds of unrelated methods. Here, the manager wraps
     the four endpoints that touch sticker rows.

Validation rules enforced here (so route handlers stay focused on
HTTP concerns):

  * Upload file size hard-capped at 512 KB. Stickers are visual
    furniture; the rendering pane scrolls past hundreds of them per
    session and bigger files hurt scrollback performance. The cap
    is configurable via ``MAX_STICKER_BYTES`` for instances that
    want to relax it.
  * Allowed MIME types: PNG, WebP, GIF (animated GIF supported but
    discouraged via the size cap), JPEG (in case someone exports
    from Photoshop without thinking).
  * ``alias`` must match ``[a-z0-9_]{2,32}`` (lowercase ASCII +
    digits + underscore, 2–32 chars). The picker treats it as a
    type-to-send shortcode, so it has to be keyboard-friendly.
  * ``display_name`` 1–64 chars, no leading/trailing whitespace,
    no embedded control characters.

The cache layout is a single key per instance — sticker lists are
small (typical instance: <100 stickers) and changes are rare
(admin uploads a few per week). One key means cache invalidation
is one ``delete``: any write goes through the manager and stamps
out the cache so the next read goes to Postgres.
"""

from __future__ import annotations

import re
import uuid
from typing import TYPE_CHECKING

from fastapi import HTTPException, UploadFile
from loguru import logger

from pufferblow.api.cache.memcache import get_cache
from pufferblow.api.errors import ApiError, ErrorCode

if TYPE_CHECKING:
    from pufferblow.api.database.database_handler import DatabaseHandler
    from pufferblow.api.storage.storage_manager import StorageManager


# Hard upload cap. Bigger files render fine in the picker but cost
# scroll perf in the message list — every other message that uses
# the sticker pulls the same file. 512 KB is comfortable for high-
# quality WebP / PNG at the 128×128 display size used in the
# renderer; the picker thumbs further at 64×64 via lazy load.
MAX_STICKER_BYTES = 512 * 1024

# Allowed MIME types at the upload boundary. The storage manager's
# auto-categoriser already routes these to the ``stickers/``
# subdirectory; we still check explicitly because someone could
# spoof a ``.png`` extension on a 50 MB MP4 and slip past the
# extension-based router. Server-side MIME sniffing happens inside
# ``StorageManager.upload_file`` via the magic-bytes path.
ALLOWED_STICKER_MIME_TYPES = {
    "image/png",
    "image/webp",
    "image/gif",
    "image/jpeg",
}

# Cache TTL — 5 minutes. Library changes infrequently; staler than
# that and admins get confused that their just-added sticker isn't
# showing up. We invalidate eagerly on every write so the TTL is
# really a backstop for missed invalidations (e.g. a process that
# crashed between commit and delete).
STICKERS_CACHE_TTL_SECONDS = 300

_ALIAS_PATTERN = re.compile(r"^[a-z0-9_]{2,32}$")
_DISPLAY_NAME_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]{1,64}$")


def stickers_list_key(host_port: str) -> str:
    """Cache key for the active-sticker list on one instance.

    The key is keyed on ``host_port`` rather than a generic instance
    id because that's what the rest of the system uses to scope
    per-instance state (see ``server_key`` / ``user_key``). A
    multi-tenant deployment would shard naturally on this key.
    """
    return f"pb:stickers:active:{host_port}"


class StickersError(Exception):
    """Raised for any client-recoverable sticker-management error.

    Carries a ``status_code`` so the route layer can translate it to
    the right HTTP status without re-matching exception classes —
    same pattern ``FriendsError`` uses.
    """

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


def _validate_alias(alias: str | None) -> str | None:
    """Normalise + validate an alias string. Returns the cleaned form
    or ``None`` (no alias)."""
    if alias is None:
        return None
    cleaned = alias.strip().lower()
    if not cleaned:
        return None
    if not _ALIAS_PATTERN.match(cleaned):
        raise ApiError(
            ErrorCode.STICKERS_INVALID_ALIAS,
            details={"alias": cleaned},
        )
    return cleaned


def _validate_display_name(display_name: str) -> str:
    cleaned = display_name.strip()
    if not cleaned:
        raise ApiError(
            ErrorCode.STICKERS_INVALID_DISPLAY_NAME,
            user_message="A name for the sticker is required.",
        )
    if not _DISPLAY_NAME_PATTERN.match(cleaned):
        raise ApiError(ErrorCode.STICKERS_INVALID_DISPLAY_NAME)
    return cleaned


class StickersManager:
    """Sticker library lifecycle: upload, list, patch, delete."""

    def __init__(
        self,
        database_handler: "DatabaseHandler",
        storage_manager: "StorageManager",
        config,
    ) -> None:
        self.database_handler = database_handler
        self.storage_manager = storage_manager
        self.config = config
        # Two-tier cache: in-process LRU in front of memcached.
        # ``get_cache`` is a process singleton — no per-instance
        # state to worry about.
        self._cache = get_cache(config)
        # Instance host_port used for cache key scoping. Pulled from
        # the server row on first cache miss because some test
        # harnesses skip the config-side host_port wiring.
        self._host_port_cached: str | None = None

    # ── Cache helpers ────────────────────────────────────────────
    def _host_port(self) -> str:
        if self._host_port_cached:
            return self._host_port_cached
        try:
            server = self.database_handler.get_server()
            self._host_port_cached = server.server_id if server else "default"
        except Exception:
            self._host_port_cached = "default"
        return self._host_port_cached

    def _cache_key(self) -> str:
        return stickers_list_key(self._host_port())

    def _invalidate_cache(self) -> None:
        try:
            self._cache.delete(self._cache_key())
        except Exception as exc:
            # Cache-delete failures are non-fatal — the TTL will
            # eventually clear the stale entry. Worst case the
            # admin sees a 5-minute lag on their library change.
            logger.warning("Failed to invalidate sticker cache: {err}", err=str(exc))

    # ── Public surface ───────────────────────────────────────────
    async def upload_sticker(
        self,
        file: UploadFile,
        user_id: str,
        display_name: str,
        alias: str | None = None,
    ) -> dict:
        """Upload a new sticker. Returns the row wire shape.

        Raises ``StickersError`` for client-recoverable conditions:
        wrong MIME, too large, duplicate alias.
        """
        # Validate metadata first so we don't hit storage on a bad
        # request. Both raises surface as 400 with a clear message.
        cleaned_name = _validate_display_name(display_name)
        cleaned_alias = _validate_alias(alias)

        # Pre-check the alias uniqueness against the DB so we get a
        # clean 409 rather than letting the storage upload run and
        # then erroring on commit (which leaks a file).
        if cleaned_alias and self.database_handler.get_sticker_by_alias(cleaned_alias):
            raise ApiError(
                ErrorCode.STICKERS_ALIAS_TAKEN,
                user_message=f"The shortcode ‘:{cleaned_alias}:’ is already in use.",
                details={"alias": cleaned_alias},
            )

        # Sniff content-type from the multipart header. Real MIME
        # verification happens inside ``StorageManager.upload_file``
        # via magic bytes — this is just a fast pre-flight to bail
        # before reading the body.
        content_type = (file.content_type or "").lower()
        if content_type and content_type not in ALLOWED_STICKER_MIME_TYPES:
            raise ApiError(
                ErrorCode.STICKERS_UNSUPPORTED_TYPE,
                details={"received_type": content_type},
            )

        try:
            storage_url, _is_duplicate, original_filename, mime_type, file_size = (
                await self.storage_manager.upload_file(
                    file=file,
                    user_id=user_id,
                    reference_type="sticker",
                    force_category="stickers",
                    check_duplicates=True,
                )
            )
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("Sticker storage upload failed: {err}", err=str(exc))
            raise ApiError(
                ErrorCode.STORAGE_UPLOAD_FAILED,
                message=f"Sticker storage upload failed: {exc}",
            )

        # Post-upload MIME check — even if the multipart header lied,
        # the storage manager re-derives mime from magic bytes.
        if mime_type and mime_type.lower() not in ALLOWED_STICKER_MIME_TYPES:
            # File made it to disk; ref-count cleanup happens in the
            # background via the orphan-file cleaner. Logging the
            # leak so it's visible if it ever piles up.
            logger.warning(
                "Sticker upload had bad final MIME {mime}: {filename}",
                mime=mime_type,
                filename=original_filename,
            )
            raise ApiError(
                ErrorCode.STICKERS_UNSUPPORTED_TYPE,
                details={"detected_type": mime_type},
            )

        if file_size and file_size > MAX_STICKER_BYTES:
            logger.warning(
                "Sticker upload exceeded size cap: {size} bytes ({filename})",
                size=file_size,
                filename=original_filename,
            )
            raise ApiError(
                ErrorCode.STICKERS_TOO_LARGE,
                details={"size_bytes": file_size, "limit_bytes": MAX_STICKER_BYTES},
            )

        sticker_id = self.database_handler.add_sticker_to_catalog(
            sticker_url=storage_url,
            filename=original_filename,
            uploaded_by=uuid.UUID(user_id),
            display_name=cleaned_name,
            alias=cleaned_alias,
        )

        self._invalidate_cache()
        row = self.database_handler.get_sticker_by_id(sticker_id)
        if row is None:
            # Race: row was inserted then deleted concurrently. Very
            # unlikely; log and return a synthesised dict so the
            # caller still gets a 201.
            logger.warning("Sticker row vanished post-insert: {id}", id=sticker_id)
            return {
                "sticker_id": sticker_id,
                "sticker_url": storage_url,
                "filename": original_filename,
                "display_name": cleaned_name,
                "alias": cleaned_alias,
                "uploaded_by": user_id,
                "usage_count": 1,
                "is_active": True,
                "created_at": None,
                "updated_at": None,
            }
        return row.to_dict()

    def list_active(self) -> list[dict]:
        """Return all active stickers, picker-ordered.

        Cached for ``STICKERS_CACHE_TTL_SECONDS``. The picker calls
        this on every chat open so the cache is doing real work.
        """
        key = self._cache_key()
        try:
            cached = self._cache.get(key)
            if cached is not None:
                return cached
        except Exception as exc:
            logger.warning("Sticker cache read failed: {err}", err=str(exc))

        rows = self.database_handler.list_server_stickers(
            limit=200, offset=0, include_inactive=False
        )
        try:
            self._cache.set(key, rows, ttl=STICKERS_CACHE_TTL_SECONDS)
        except Exception as exc:
            logger.warning("Sticker cache write failed: {err}", err=str(exc))
        return rows

    def list_all(self) -> list[dict]:
        """Return all stickers including deactivated, no cache.

        For the admin management UI only. Skips the cache because
        the admin view is rare-hit and we want freshness over
        latency there.
        """
        return self.database_handler.list_server_stickers(
            limit=500, offset=0, include_inactive=True
        )

    def get(self, sticker_id: str) -> dict | None:
        row = self.database_handler.get_sticker_by_id(sticker_id)
        return row.to_dict() if row else None

    def update(
        self,
        sticker_id: str,
        display_name: str | None = None,
        alias: str | None = None,
        is_active: bool | None = None,
    ) -> dict:
        """Patch a sticker's metadata. Empty alias clears it."""
        cleaned_name = (
            _validate_display_name(display_name) if display_name is not None else None
        )
        cleaned_alias = (
            _validate_alias(alias) if alias is not None and alias.strip() else (
                "" if alias is not None else None
            )
        )
        # Treat empty string explicitly as "clear the alias".
        if alias is not None and not alias.strip():
            cleaned_alias = ""

        if cleaned_alias and cleaned_alias not in ("", None):
            existing = self.database_handler.get_sticker_by_alias(cleaned_alias)
            if existing and existing.sticker_id != sticker_id:
                raise ApiError(
                    ErrorCode.STICKERS_ALIAS_TAKEN,
                    details={"alias": cleaned_alias},
                )

        updated = self.database_handler.update_sticker_metadata(
            sticker_id=sticker_id,
            display_name=cleaned_name,
            alias=cleaned_alias,
            is_active=is_active,
        )
        if updated is None:
            raise ApiError(
                ErrorCode.STICKERS_NOT_FOUND,
                details={"sticker_id": sticker_id},
            )
        self._invalidate_cache()
        return updated.to_dict()

    def delete(self, sticker_id: str) -> bool:
        """Hard-delete a sticker. Returns False if not found.

        Storage cleanup: the underlying file lives on in
        ``file_objects`` until its ref-count hits zero. We DON'T
        decrement the ref here — the storage manager handles
        deletion through its own orphan-cleanup background task,
        which catches files unreferenced by any current row. This
        keeps the sticker delete a pure DB operation and avoids
        race conditions where two admins delete in parallel.
        """
        deleted_url = self.database_handler.delete_sticker(sticker_id)
        if deleted_url is None:
            return False
        self._invalidate_cache()
        return True

    def bump_usage_from_attachments(self, attachments: list[dict] | None) -> None:
        """Bump usage_count for any attachments carrying a sticker_id.

        Called from the message-send path so the picker can rank
        most-used stickers first. Best-effort — a bump failure
        doesn't fail the send.

        Recognises two shapes:
          * Typed: ``{"type": "sticker", "sticker_id": "<uuid>"}``
          * Inferred: any attachment whose URL contains
            ``/storage/`` and matches a known sticker URL (covers
            DM messages where attachments are bare URL strings).
        """
        if not attachments:
            return
        sticker_ids: list[str] = []
        for att in attachments:
            if not isinstance(att, dict):
                continue
            if att.get("type") == "sticker" and att.get("sticker_id"):
                sticker_ids.append(str(att["sticker_id"]))
        for sid in sticker_ids:
            try:
                self.database_handler.increment_sticker_usage(sid)
            except Exception as exc:
                logger.debug(
                    "Failed to bump sticker usage_count for {sid}: {err}",
                    sid=sid, err=str(exc),
                )
        if sticker_ids:
            # One invalidation per send is plenty — the cache will
            # rebuild on next read with the fresh ordering.
            self._invalidate_cache()

    # ── Reaction support ─────────────────────────────────────────
    def is_sticker_reaction_key(self, key: str) -> bool:
        """``True`` if the reaction key encodes a sticker reference."""
        return isinstance(key, str) and key.startswith("sticker:")

    def validate_reaction_key(self, key: str) -> str:
        """Validate a reaction key. Returns the canonical form.

        Accepts:
          * Unicode emoji (any non-empty short string that doesn't
            start with the ``sticker:`` prefix). We don't try to
            verify Unicode-emoji-ness here — the input length cap
            in the route + the column width cap together prevent
            abuse, and we'd rather not lock the picker to a
            specific Unicode version.
          * Sticker references: ``sticker:<sticker_id>``. The
            sticker_id must exist and the sticker must be active
            (deactivated stickers can't be newly reacted with).

        Raises ``StickersError`` on invalid keys.
        """
        if not isinstance(key, str) or not key:
            raise ApiError(
                ErrorCode.VALIDATION_FIELD_REQUIRED,
                user_message="A reaction value is required.",
                details={"field": "emoji"},
            )
        if len(key) > 64:
            raise ApiError(
                ErrorCode.VALIDATION_FIELD_RANGE,
                user_message="That reaction value is too long.",
                details={"field": "emoji", "limit": 64, "actual": len(key)},
            )
        if not self.is_sticker_reaction_key(key):
            return key  # plain emoji, no further validation
        sticker_id = key.removeprefix("sticker:")
        sticker = self.database_handler.get_sticker_by_id(sticker_id)
        if sticker is None or not sticker.is_active:
            raise ApiError(
                ErrorCode.STICKERS_NOT_AVAILABLE,
                details={"sticker_id": sticker_id},
            )
        return key
