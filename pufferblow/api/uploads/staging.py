"""Where files sent over the socket wait until the message that carries them is created.

A client sends ``upload.begin`` (name, type, size), then ``upload.chunk`` frames in order, then names the
upload in ``message.create`` (``upload_ids``). The bytes are held here, owned by the principal that began the
upload, and handed to the same storage code the HTTP route uses. Nothing is trusted from the client: the size
is capped, chunks must arrive in order and add up exactly, uploads expire, and a principal and the whole
process have a limit on what they may hold at once.

The store is per process, like the sockets it serves. It is only touched from the event loop.
"""

from __future__ import annotations

import io
import secrets
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from fastapi import UploadFile
from starlette.datastructures import Headers

from pufferblow.api.errors import ApiError, ErrorCode

#: Largest chunk a client may send, in raw bytes. Base64 inflates it by a third, and a frame may be 64 KiB.
CHUNK_BYTES = 32 * 1024
MAX_OPEN_PER_PRINCIPAL = 5
MAX_STAGED_BYTES_TOTAL = 512 * 1024 * 1024
TTL_SECONDS = 10 * 60
#: Held in memory up to this size, on disk beyond it.
SPOOL_BYTES = 1024 * 1024


@dataclass
class StagedUpload:
    upload_id: str
    owner: str
    name: str
    content_type: str | None
    size: int
    created: float
    file: tempfile.SpooledTemporaryFile = field(repr=False)
    received: int = 0
    next_index: int = 0

    @property
    def complete(self) -> bool:
        return self.received == self.size


class UploadStaging:
    def __init__(
        self,
        max_file_bytes: Callable[[], int],
        *,
        clock: Callable[[], float] = time.monotonic,
        ttl_seconds: float = TTL_SECONDS,
        max_total_bytes: int = MAX_STAGED_BYTES_TOTAL,
    ) -> None:
        """``max_file_bytes()`` is the instance's limit for one message's attachments."""
        self._max_file_bytes = max_file_bytes
        self._clock = clock
        self._ttl = ttl_seconds
        self._max_total = max_total_bytes
        self._uploads: dict[str, StagedUpload] = {}

    # ── bookkeeping ────────────────────────────────────────────

    def _purge_expired(self) -> None:
        now = self._clock()
        for upload_id in [i for i, u in self._uploads.items() if now - u.created > self._ttl]:
            self._drop(upload_id)

    def _drop(self, upload_id: str) -> None:
        upload = self._uploads.pop(upload_id, None)
        if upload is not None:
            upload.file.close()

    def _owned(self, owner: str, upload_id: str) -> StagedUpload:
        """The upload, or the same "not found" whether it never existed, expired, or is someone else's."""
        self._purge_expired()
        upload = self._uploads.get(upload_id)
        if upload is None or upload.owner != owner:
            raise ApiError(ErrorCode.RESOURCE_NOT_FOUND, details={"resource": "upload"})
        return upload

    def staged_bytes(self) -> int:
        return sum(u.size for u in self._uploads.values())

    def open_count(self, owner: str | None = None) -> int:
        return sum(1 for u in self._uploads.values() if owner is None or u.owner == owner)

    # ── the three commands ─────────────────────────────────────

    def begin(self, owner: str, name: str, content_type: str | None, size: int) -> StagedUpload:
        self._purge_expired()
        limit = self._max_file_bytes()
        if size < 1 or size > limit:
            raise ApiError(
                ErrorCode.VALIDATION_FIELD_RANGE,
                user_message=f"A file must be between 1 byte and {limit // (1024 * 1024)}MB.",
                details={"field": "size", "max_bytes": limit},
            )
        if self.open_count(owner) >= MAX_OPEN_PER_PRINCIPAL:
            raise ApiError(
                ErrorCode.RATE_LIMIT_EXCEEDED,
                user_message="Too many uploads are open. Finish or cancel one first.",
                retry_after_seconds=5,
            )
        if self.staged_bytes() + size > self._max_total:
            raise ApiError(
                ErrorCode.RATE_LIMIT_EXCEEDED,
                user_message="The server is receiving too many uploads right now. Try again shortly.",
                retry_after_seconds=10,
            )
        upload = StagedUpload(
            upload_id=f"upl_{secrets.token_urlsafe(12)}",
            owner=owner,
            name=name,
            content_type=content_type,
            size=size,
            created=self._clock(),
            file=tempfile.SpooledTemporaryFile(max_size=SPOOL_BYTES),
        )
        self._uploads[upload.upload_id] = upload
        return upload

    def append(self, owner: str, upload_id: str, index: int, raw: bytes) -> tuple[StagedUpload, bool]:
        """Add the next chunk. Returns the upload and whether this exact chunk was already stored.

        A retry of the chunk just accepted (its acknowledgment was lost) is a no-op; any other index but the
        next one is refused, so the file cannot be reassembled wrongly.
        """
        upload = self._owned(owner, upload_id)
        if len(raw) < 1 or len(raw) > CHUNK_BYTES:
            raise ApiError(
                ErrorCode.VALIDATION_FIELD_RANGE,
                user_message=f"A chunk is 1 to {CHUNK_BYTES} bytes.",
                details={"field": "data", "max_bytes": CHUNK_BYTES},
            )
        if index == upload.next_index - 1:
            return upload, True
        if index != upload.next_index:
            raise ApiError(
                ErrorCode.VALIDATION_FIELD_RANGE,
                user_message=f"Expected chunk {upload.next_index}, got {index}.",
                details={"field": "index", "expected": upload.next_index},
            )
        if upload.received + len(raw) > upload.size:
            raise ApiError(
                ErrorCode.VALIDATION_FIELD_RANGE,
                user_message="The chunks add up to more than the size given at the start.",
                details={"field": "data"},
            )
        upload.file.write(raw)
        upload.received += len(raw)
        upload.next_index += 1
        return upload, False

    def abort(self, owner: str, upload_id: str) -> None:
        self._owned(owner, upload_id)
        self._drop(upload_id)

    # ── using the uploads ──────────────────────────────────────

    def collect(self, owner: str, upload_ids: list[str]) -> list[UploadFile]:
        """The named uploads as files ready for storage. They stay staged until :meth:`discard`, so a message
        that fails to send can be retried with the same ids."""
        files: list[UploadFile] = []
        for upload_id in dict.fromkeys(upload_ids):  # in order, each once
            upload = self._owned(owner, upload_id)
            if not upload.complete:
                raise ApiError(
                    ErrorCode.VALIDATION_FIELD_RANGE,
                    user_message="An upload is not finished yet.",
                    details={"field": "upload_ids", "upload_id": upload_id, "received": upload.received, "size": upload.size},
                )
            upload.file.seek(0)
            # The storage layer reads the stream once; a copy keeps the staged bytes intact for a retry.
            payload = io.BytesIO(upload.file.read())
            headers = Headers({"content-type": upload.content_type}) if upload.content_type else None
            files.append(UploadFile(file=payload, filename=upload.name, headers=headers))
        return files

    def discard(self, owner: str, upload_ids: list[str]) -> None:
        for upload_id in upload_ids:
            upload = self._uploads.get(upload_id)
            if upload is not None and upload.owner == owner:
                self._drop(upload_id)
