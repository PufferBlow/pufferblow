"""
Storage Backend Abstraction for Pufferblow

This module provides a unified interface for different storage backends
including local storage, AWS S3, and other cloud storage providers.
"""

from abc import ABC, abstractmethod
from typing import Any


class StorageBackend(ABC):
    """Abstract base class for storage backends"""

    def __init__(self, config: dict[str, Any]):
        """Initialize the instance."""
        self.config = config

    @abstractmethod
    async def upload_file(
        self, content: bytes, path: str, metadata: dict[str, Any] | None = None
    ) -> str:
        """
        Upload a file to storage

        Args:
            content: File content as bytes
            path: Storage path/key
            metadata: Optional metadata

        Returns:
            Public URL or storage path
        """
        pass

    @abstractmethod
    async def download_file(self, path: str) -> bytes:
        """
        Download a file from storage

        Args:
            path: Storage path/key

        Returns:
            File content as bytes
        """
        pass

    @abstractmethod
    async def delete_file(self, path: str) -> bool:
        """
        Delete a file from storage

        Args:
            path: Storage path/key

        Returns:
            True if deleted successfully
        """
        pass

    @abstractmethod
    async def file_exists(self, path: str) -> bool:
        """
        Check if a file exists in storage

        Args:
            path: Storage path/key

        Returns:
            True if file exists
        """
        pass

    @abstractmethod
    async def get_file_url(self, path: str, expires_in: int | None = None) -> str:
        """
        Get a public URL for the file

        Args:
            path: Storage path/key
            expires_in: Optional expiration time in seconds for signed URLs

        Returns:
            Public URL
        """
        pass

    @abstractmethod
    async def list_files(self, prefix: str = "") -> list[str]:
        """
        List files with given prefix

        Args:
            prefix: Path prefix to filter files

        Returns:
            List of file paths
        """
        pass

    @abstractmethod
    async def get_storage_info(self) -> dict[str, Any]:
        """
        Get storage backend information and stats

        Returns:
            Dict with storage info (used space, total space, etc.)
        """
        pass

    @abstractmethod
    async def check_space_available(self, size_bytes: int) -> bool:
        """
        Check if there's enough space for a file of given size

        Args:
            size_bytes: Size of file to check

        Returns:
            True if space is available
        """
        pass
