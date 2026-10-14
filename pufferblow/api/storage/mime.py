"""MIME detection with a graceful fallback.

``python-magic`` needs the native libmagic library. On machines where it is
missing or broken (commonly Windows), importing it used to take the whole storage
subsystem down, which also disabled uploads that do not need it. This module
loads libmagic when it works and otherwise falls back to a small signature
sniffer, so storage stays available. Extension allow-lists and image verification
in the storage manager still apply either way.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

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


def _first_windows_libmagic() -> str | None:
    """The DLL python-magic would load on Windows, searched in its own order (`magic/loader.py`)."""
    from ctypes.util import find_library

    found = find_library("magic")
    if found:
        return found
    for prefix in ("libmagic", "magic1", "cygmagic-1", "libmagic-1", "msys-magic-1"):
        local = f"./{prefix}.dll"
        if os.path.exists(local):
            return local
        found = find_library(prefix)
        if found:
            return found
    return None


def _libmagic_would_crash() -> bool:
    """True when importing `magic` would load a libmagic built for MSYS/Cygwin.

    On Windows python-magic takes any libmagic on PATH, including Git for Windows'
    `msys-magic-1.dll`. Loading that into a native Python is an access violation, which looks
    like `import magic` hanging. That can't be caught once it happens, so check first.
    python-magic-bin ships its own native DLL inside the package and is fine.
    """
    if sys.platform != "win32":
        return False
    spec = importlib.util.find_spec("magic")
    if spec is None or spec.origin is None:
        return False  # not installed: the import fails cleanly
    if any(Path(spec.origin).parent.rglob("*.dll")):
        return False  # python-magic-bin's bundled library
    library = _first_windows_libmagic()
    return library is not None and Path(library).name.lower().startswith(("msys-", "cyg"))


def create_mime_detector():
    """Return a libmagic detector when available, otherwise the signature fallback."""
    if _libmagic_would_crash():
        logger.warning(
            "The only libmagic on PATH is an MSYS/Cygwin build (Git for Windows ships one), which "
            "crashes a native Python; using basic file-type detection for uploads. Install "
            "python-magic-bin for full detection."
        )
        return SignatureMimeDetector()
    try:
        import magic

        return magic.Magic(mime=True)
    except Exception as exc:  # ImportError, or libmagic failing to load
        logger.warning(
            f"libmagic is unavailable ({exc!r}); using basic file-type detection for uploads. "
            "Install libmagic (python-magic-bin on Windows) for full detection."
        )
        return SignatureMimeDetector()
