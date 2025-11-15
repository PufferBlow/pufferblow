"""
Local Storage Backend for Pufferblow

Provides local file system storage with space allocation and monitoring.
"""

from pathlib import Path
from typing import Any

import psutil
from fastapi import HTTPException

from .storage_backend import StorageBackend


class LocalStorageBackend(StorageBackend):
    """Local file system storage backend with space allocation"""

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)

        # Storage configuration
        self.storage_path = Path(
            config.get("storage_path", "~/.pufferblow/storage")
        ).expanduser()
        self.allocated_space_gb = config.get("allocated_space_gb", 10)  # Default 10GB
        self.base_url = config.get("base_url", "/storage")
        self.api_host = config.get("api_host", "127.0.0.1")
        self.api_port = config.get("api_port", 7575)

        # Create storage directory
        self.storage_path.mkdir(parents=True, exist_ok=True)

        # Calculate allocated bytes
        self.allocated_bytes = self.allocated_space_gb * 1024 * 1024 * 1024

    async def upload_file(
        self, content: bytes, path: str, metadata: dict[str, Any] | None = None
    ) -> str:
        """Upload file to local storage"""
        file_size = len(content)

        # Check space availability
        if not await self.check_space_available(file_size):
            raise HTTPException(
                status_code=507,  # Insufficient Storage
                detail=f"Insufficient storage space. Allocated: {self.allocated_space_gb}GB, "
                f"Used: {await self._get_used_space_gb():.2f}GB",
            )

        # Create full file path
        full_path = self.storage_path / path
        full_path.parent.mkdir(parents=True, exist_ok=True)

        # Write file
        with open(full_path, "wb") as f:
            f.write(content)

        # Return full URL with host:port
        return f"http://{self.api_host}:{self.api_port}{self.base_url}/{path}"

    async def download_file(self, path: str) -> bytes:
        """Download file from local storage"""
        full_path = self.storage_path / path

        if not full_path.exists():
            raise HTTPException(status_code=404, detail="File not found")

        with open(full_path, "rb") as f:
            return f.read()

    async def delete_file(self, path: str) -> bool:
        """Delete file from local storage"""
        full_path = self.storage_path / path

        if full_path.exists():
            full_path.unlink()
            return True
        return False

    async def file_exists(self, path: str) -> bool:
        """Check if file exists"""
        full_path = self.storage_path / path
        return full_path.exists()

    async def get_file_url(self, path: str, expires_in: int | None = None) -> str:
        """Get file URL (local files don't expire)"""
        return f"http://{self.api_host}:{self.api_port}{self.base_url}/{path}"

    async def list_files(self, prefix: str = "") -> list[str]:
        """List files with prefix"""
        search_path = self.storage_path / prefix if prefix else self.storage_path

        if not search_path.exists():
            return []

        files = []
        if search_path.is_file():
            files.append(str(search_path.relative_to(self.storage_path)))
        else:
            for file_path in search_path.rglob("*"):
                if file_path.is_file():
                    files.append(str(file_path.relative_to(self.storage_path)))

        return files

    async def get_storage_info(self) -> dict[str, Any]:
        """Get storage information"""
        used_bytes = await self._get_used_space_bytes()
        disk_usage = psutil.disk_usage(str(self.storage_path))

        return {
            "provider": "local",
            "storage_path": str(self.storage_path),
            "allocated_gb": self.allocated_space_gb,
            "used_gb": used_bytes / (1024**3),
            "used_percentage": (
                (used_bytes / self.allocated_bytes) * 100
                if self.allocated_bytes > 0
                else 0
            ),
            "disk_free_gb": disk_usage.free / (1024**3),
            "disk_total_gb": disk_usage.total / (1024**3),
            "files_count": await self._count_files(),
        }

    async def check_space_available(self, size_bytes: int) -> bool:
        """Check if space is available for file"""
        current_used = await self._get_used_space_bytes()
        return (current_used + size_bytes) <= self.allocated_bytes

    async def _get_used_space_bytes(self) -> int:
        """Get total used space in bytes"""
        total_size = 0
        for file_path in self.storage_path.rglob("*"):
            if file_path.is_file():
                total_size += file_path.stat().st_size
        return total_size

    async def _get_used_space_gb(self) -> float:
        """Get used space in GB"""
        return (await self._get_used_space_bytes()) / (1024**3)

    async def _count_files(self) -> int:
        """Count total files in storage"""
        count = 0
        for _ in self.storage_path.rglob("*"):
            count += 1
        return count

    async def cleanup_orphaned_files(self, valid_files: list[str]) -> int:
        """
        Remove files not in the valid_files list

        Args:
            valid_files: List of relative file paths that should be kept

        Returns:
            Number of files deleted
        """
        valid_paths = {self.storage_path / path for path in valid_files}
        deleted_count = 0

        for file_path in self.storage_path.rglob("*"):
            if file_path.is_file() and file_path not in valid_paths:
                file_path.unlink()
                deleted_count += 1

        return deleted_count
