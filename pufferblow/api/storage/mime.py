"""MIME detection with a graceful fallback.

``python-magic`` needs the native libmagic library. On machines where it is
missing or broken (commonly Windows), importing it used to take the whole storage
subsystem down, which also disabled uploads that do not need it. This module
loads libmagic when it works and otherwise falls back to a small signature
sniffer, so storage stays available. Extension allow-lists and image verification
in the storage manager still apply either way.
"""

from __future__ import annotations

from loguru import logger

_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"%PDF-", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"OggS", "audio/ogg"),
    (b"ID3", "audio/mpeg"),
    (b"fLaC", "audio/flac"),
)


class SignatureMimeDetector:
    """Detects the common upload types from their leading bytes."""

    def from_buffer(self, content: bytes) -> str:
        head = content[:16]
        for signature, mime in _SIGNATURES:
            if head.startswith(signature):
                return mime
        if head[:4] == b"RIFF" and content[8:12] == b"WEBP":
            return "image/webp"
        if head[:4] == b"RIFF" and content[8:12] == b"WAVE":
            return "audio/wav"
        if content[4:8] == b"ftyp":
            return "video/mp4"
        if head[:4] == b"\x1aE\xdf\xa3":
            return "video/webm"
        try:
            content[:4096].decode("utf-8")
            return "text/plain"
        except UnicodeDecodeError:
            return "application/octet-stream"


def create_mime_detector():
    """Return a libmagic detector when available, otherwise the signature fallback."""
    try:
        import magic

        return magic.Magic(mime=True)
    except Exception as exc:  # ImportError, or libmagic failing to load
        logger.warning(
            f"libmagic is unavailable ({exc!r}); using basic file-type detection for uploads. "
            "Install libmagic (python-magic-bin on Windows) for full detection."
        )
        return SignatureMimeDetector()
