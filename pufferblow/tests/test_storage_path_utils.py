from __future__ import annotations

import asyncio

import pytest

from pufferblow.api.storage.local_storage import LocalStorageBackend
from pufferblow.api.storage.path_utils import (
    extract_local_media_path,
    normalize_storage_relative_path,
)


def test_normalize_storage_relative_path_accepts_valid_relative_paths() -> None:
    assert normalize_storage_relative_path("avatars/test.png") == "avatars/test.png"
    assert normalize_storage_relative_path("/avatars\\nested/test.png") == "avatars/nested/test.png"


def test_normalize_storage_relative_path_rejects_path_traversal() -> None:
    with pytest.raises(ValueError):
        normalize_storage_relative_path("../secrets.txt")


def test_extract_local_media_path_ignores_remote_absolute_urls() -> None:
    path = extract_local_media_path(
        "https://remote.example/storage/abc",
        api_host="127.0.0.1",
        api_port=7575,
    )

    assert path is None


def test_local_storage_backend_rejects_traversal_upload(tmp_path) -> None:
    backend = LocalStorageBackend(
        {
            "storage_path": str(tmp_path / "storage"),
            "base_url": "/storage",
            "api_host": "127.0.0.1",
            "api_port": 7575,
        }
    )

    async def runner() -> None:
        with pytest.raises(ValueError):
            await backend.upload_file(b"bad", "../escape.txt")

    asyncio.run(runner())
