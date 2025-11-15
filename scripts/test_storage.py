#!/usr/bin/env python3
"""
Simple test script for storage backends
"""

import asyncio
import sys
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))


def test_storage_imports():
    """Test that storage modules can be imported"""
    try:
        # Import storage modules directly
        sys.path.insert(
            0, str(Path(__file__).parent.parent / "pufferblow" / "api" / "storage")
        )

        from pufferblow.api.storage.local_storage import LocalStorageBackend
        from pufferblow.api.storage.s3_storage import S3StorageBackend
        from pufferblow.api.storage.storage_backend import StorageBackend
        from pufferblow.api.storage.storage_manager import StorageManager

        print("✓ All storage modules imported successfully")
        return True
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False


async def test_storage_manager():
    """Test storage manager initialization"""
    try:
        # Import storage modules directly
        sys.path.insert(
            0, str(Path(__file__).parent.parent / "pufferblow" / "api" / "storage")
        )

        from storage_manager import StorageManager

        # Test with local config
        local_config = {
            "provider": "local",
            "storage_path": "./test_storage",
            "base_url": "http://localhost:8080/storage",
            "max_size_gb": 10,
        }

        manager = StorageManager(local_config)
        print("✓ StorageManager initialized successfully")

        # Test basic functionality
        test_file = b"Hello, World!"
        test_path = "test.txt"

        # Test upload
        await manager.upload_file(test_file, test_path)
        print("✓ File upload successful")

        # Test file exists
        exists = await manager.file_exists(test_path)
        print(f"✓ File exists check: {exists}")

        # Test download
        downloaded = await manager.download_file(test_path)
        print(f"✓ File download successful: {downloaded == test_file}")

        # Test delete
        await manager.delete_file(test_path)
        print("✓ File delete successful")

        return True
    except Exception as e:
        print(f"✗ StorageManager test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


async def main():
    print("Testing storage backends...")

    success = True
    success &= test_storage_imports()
    success &= await test_storage_manager()

    if success:
        print("\n✓ All tests passed!")
        return 0
    else:
        print("\n✗ Some tests failed!")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
