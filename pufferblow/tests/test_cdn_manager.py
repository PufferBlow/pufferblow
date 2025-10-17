import pytest
import io
from pathlib import Path
from PIL import Image
from fastapi import UploadFile

from pufferblow.api.cdn.cdn_manager import CDNManager
from pufferblow.api.database.database_handler import DatabaseHandler
from pufferblow.api.models.config_model import Config
from pufferblow.api_initializer import api_initializer


class TestCDNManager:
    """Test CDN Manager core functionality"""

    @pytest.fixture
    def cdn_manager(self):
        """Create CDN manager instance"""
        return api_initializer.cdn_manager

    def test_cdn_manager_initialization(self, cdn_manager):
        """Test CDN manager initialization"""
        assert cdn_manager.MAX_IMAGE_SIZE_MB == 5
        assert cdn_manager.MAX_VIDEO_SIZE_MB == 50
        assert 'png' in cdn_manager.IMAGE_EXTENSIONS
        assert 'jpg' in cdn_manager.IMAGE_EXTENSIONS
        assert str(cdn_manager.config.CDN_STORAGE_PATH).startswith('/home/r0d/cdn')

    def test_update_server_limits(self, cdn_manager):
        """Test server limits update"""
        # Test with defaults (no server settings in test DB)
        cdn_manager.update_server_limits()

        # Should have default values
        assert cdn_manager.MAX_IMAGE_SIZE_MB == 5  # Default
        assert len(cdn_manager.IMAGE_EXTENSIONS) >= 1

    def test_validate_and_save_file_success(self, cdn_manager):
        """Test successful file validation and saving"""
        # Create a test image
        test_image = Image.new('RGB', (100, 100), color='red')
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format='PNG')
        image_buffer.seek(0)

        # Create UploadFile object
        file = UploadFile(filename="test.png", file=image_buffer)

        # Test parameters
        user_id = "test-user-123"
        max_size_mb = 10
        allowed_extensions = ['png', 'jpg']

        # Call the method
        result_url = cdn_manager.validate_and_save_file(
            file=file,
            user_id=user_id,
            max_size_mb=max_size_mb,
            allowed_extensions=allowed_extensions,
            subdirectory="test_subdir"
        )

        # Check result
        assert result_url.startswith("/cdn/test_subdir/")
        assert result_url.endswith(".png")

        # Check file exists on disk
        relative_path = result_url[len("/cdn/"):]
        file_path = Path(cdn_manager.config.CDN_STORAGE_PATH) / relative_path
        assert file_path.exists()

        # Clean up
        if file_path.exists():
            file_path.unlink(missing_ok=True)

    def test_validate_file_invalid_extension(self, cdn_manager):
        """Test invalid file extension"""
        # Create a test image but with invalid extension
        test_image = Image.new('RGB', (100, 100), color='blue')
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format='PNG')
        image_buffer.seek(0)

        # Create UploadFile object with invalid extension
        file = UploadFile(filename="test.invalid", file=image_buffer)

        # Test parameters
        max_size_mb = 10
        allowed_extensions = ['png', 'jpg']  # doesn't include .invalid

        # Call should raise HTTPException
        with pytest.raises(Exception) as exc_info:
            cdn_manager.validate_and_save_file(
                file=file,
                user_id="test-user",
                max_size_mb=max_size_mb,
                allowed_extensions=allowed_extensions,
                subdirectory="test"
            )

        assert "not allowed" in str(exc_info.value)

    def test_validate_file_too_large(self, cdn_manager):
        """Test file size limit validation"""
        # Create a small image but simulate it being too large
        test_image = Image.new('RGB', (10, 10), color='green')  # Very small
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format='PNG')
        image_buffer.seek(0)

        # Manually make it appear large
        fake_large_content = image_buffer.getvalue() + b'x' * (1024 * 1024)  # Add 1MB
        large_buffer = io.BytesIO(fake_large_content)
        file = UploadFile(filename="large.png", file=large_buffer)

        # Set very small limit
        max_size_mb = 0.5  # 0.5MB, much smaller than fake 1MB+

        # Call should raise HTTPException
        with pytest.raises(Exception) as exc_info:
            cdn_manager.validate_and_save_file(
                file=file,
                user_id="test-user",
                max_size_mb=max_size_mb,
                allowed_extensions=['png'],
                subdirectory="test"
            )

        assert "exceeds maximum" in str(exc_info.value)

    def test_get_file_info(self, cdn_manager):
        """Test getting file information"""
        # Create a test file directly
        test_content = b"test file content"
        test_path = Path(cdn_manager.config.CDN_STORAGE_PATH) / "test" / "info_test.txt"

        # Ensure directory exists
        test_path.parent.mkdir(parents=True, exist_ok=True)

        # Write test file
        test_path.write_bytes(test_content)

        # Create URL path
        url_path = "/cdn/test/info_test.txt"

        # Get file info
        info = cdn_manager.get_file_info(url_path)

        assert info is not None
        assert info['size'] == len(test_content)
        assert info['mime_type'] is not None

        # Clean up
        test_path.unlink(missing_ok=True)

    def test_get_file_info_not_found(self, cdn_manager):
        """Test getting info for non-existent file"""
        url_path = "/cdn/test/nonexistent.txt"
        info = cdn_manager.get_file_info(url_path)

        assert info is None

    def test_delete_file(self, cdn_manager):
        """Test file deletion"""
        # Create a test file
        test_content = b"test file to delete"
        test_path = Path(cdn_manager.config.CDN_STORAGE_PATH) / "test" / "delete_test.txt"
        test_path.parent.mkdir(parents=True, exist_ok=True)
        test_path.write_bytes(test_content)

        url_path = "/cdn/test/delete_test.txt"

        # Delete file
        deleted = cdn_manager.delete_file(url_path)

        assert deleted is True
        assert not test_path.exists()

    def test_delete_file_not_found(self, cdn_manager):
        """Test deleting non-existent file"""
        url_path = "/cdn/test/nonexistent.txt"

        deleted = cdn_manager.delete_file(url_path)

        assert deleted is False
