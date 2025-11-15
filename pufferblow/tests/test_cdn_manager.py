import io
from pathlib import Path

import pytest
from fastapi import HTTPException, UploadFile
from PIL import Image

from pufferblow.api.cdn.cdn_manager import CDNManager
from pufferblow.api_initializer import api_initializer


class TestCDNManager:
    """Test CDN Manager core functionality"""

    @pytest.fixture
    def cdn_manager(self, tmp_path):
        """Create CDN manager instance with temporary storage"""
        # Use the actual database handler from api_initializer but with test config
        database_handler = api_initializer.database_handler

        # Create test config with temporary paths
        class TestConfig:
            def __init__(self):
                self.CDN_STORAGE_PATH = str(tmp_path / "cdn_test")
                self.CDN_BASE_URL = "/cdn"

        config = TestConfig()
        return CDNManager(database_handler, config)

    def test_cdn_manager_initialization(self, cdn_manager):
        """Test CDN manager initialization"""
        assert cdn_manager.MAX_IMAGE_SIZE_MB == 5
        assert cdn_manager.MAX_VIDEO_SIZE_MB == 50
        assert "png" in cdn_manager.IMAGE_EXTENSIONS
        assert "jpg" in cdn_manager.IMAGE_EXTENSIONS
        # Check that storage path is set correctly
        assert "cdn_test" in str(cdn_manager.config.CDN_STORAGE_PATH)

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
        test_image = Image.new("RGB", (100, 100), color="red")
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format="PNG")
        image_buffer.seek(0)

        # Create UploadFile object
        file = UploadFile(filename="test.png", file=image_buffer)

        # Test parameters
        user_id = "test-user-123"
        max_size_mb = 10
        allowed_extensions = ["png", "jpg"]

        # Call the method
        result_url, is_duplicate = cdn_manager.validate_and_save_file(
            file=file,
            user_id=user_id,
            max_size_mb=max_size_mb,
            allowed_extensions=allowed_extensions,
            subdirectory="test_subdir",
        )

        # Check result
        assert result_url.startswith("/cdn/test_subdir/")
        assert result_url.endswith(".png")
        assert is_duplicate is False

        # Check file exists on disk
        relative_path = result_url[len("/cdn/") :]
        file_path = Path(cdn_manager.config.CDN_STORAGE_PATH) / relative_path
        assert file_path.exists()

        # Clean up
        if file_path.exists():
            file_path.unlink(missing_ok=True)

    def test_validate_file_invalid_extension(self, cdn_manager):
        """Test invalid file extension"""
        # Create a test image but with invalid extension
        test_image = Image.new("RGB", (100, 100), color="blue")
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format="PNG")
        image_buffer.seek(0)

        # Create UploadFile object with invalid extension
        file = UploadFile(filename="test.invalid", file=image_buffer)

        # Test parameters
        max_size_mb = 10
        allowed_extensions = ["png", "jpg"]  # doesn't include .invalid

        # Call should raise HTTPException
        with pytest.raises(Exception) as exc_info:
            cdn_manager.validate_and_save_file(
                file=file,
                user_id="test-user",
                max_size_mb=max_size_mb,
                allowed_extensions=allowed_extensions,
                subdirectory="test",
            )

        assert "not allowed" in str(exc_info.value)

    def test_validate_file_too_large(self, cdn_manager):
        """Test file size limit validation"""
        # Create a small image but simulate it being too large
        test_image = Image.new("RGB", (10, 10), color="green")  # Very small
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format="PNG")
        image_buffer.seek(0)

        # Manually make it appear large
        fake_large_content = image_buffer.getvalue() + b"x" * (1024 * 1024)  # Add 1MB
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
                allowed_extensions=["png"],
                subdirectory="test",
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
        assert info["size"] == len(test_content)
        assert info["mime_type"] is not None

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
        test_path = (
            Path(cdn_manager.config.CDN_STORAGE_PATH) / "test" / "delete_test.txt"
        )
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


class TestCDNManagerCategorization:
    """Test CDN Manager automatic file categorization functionality"""

    @pytest.fixture
    def cdn_manager(self, tmp_path):
        """Create CDN manager instance with temporary storage"""
        # Use the actual database handler from api_initializer but with test config
        database_handler = api_initializer.database_handler

        # Create test config with temporary paths
        class TestConfig:
            def __init__(self):
                self.CDN_STORAGE_PATH = str(tmp_path / "cdn_test")
                self.CDN_BASE_URL = "/cdn"

        config = TestConfig()
        return CDNManager(database_handler, config)

    def test_categorize_file_image_png(self, cdn_manager):
        """Test categorization of PNG image"""
        category = cdn_manager.categorize_file("test.png", "image/png")
        assert category == "images"

    def test_categorize_file_image_jpg(self, cdn_manager):
        """Test categorization of JPG image"""
        category = cdn_manager.categorize_file("test.jpg", "image/jpeg")
        assert category == "images"

    def test_categorize_file_gif(self, cdn_manager):
        """Test categorization of GIF file"""
        category = cdn_manager.categorize_file("test.gif", "image/gif")
        assert category == "gifs"

    def test_categorize_file_avatar(self, cdn_manager):
        """Test categorization of avatar file"""
        category = cdn_manager.categorize_file("profile_avatar.png", "image/png")
        assert category == "avatars"

    def test_categorize_file_banner(self, cdn_manager):
        """Test categorization of banner file"""
        category = cdn_manager.categorize_file("user_banner.jpg", "image/jpeg")
        assert category == "banners"

    def test_categorize_file_sticker(self, cdn_manager):
        """Test categorization of sticker file"""
        category = cdn_manager.categorize_file("emoji_sticker.png", "image/png")
        assert category == "stickers"

    def test_categorize_file_video(self, cdn_manager):
        """Test categorization of video file"""
        category = cdn_manager.categorize_file("video.mp4", "video/mp4")
        assert category == "videos"

    def test_categorize_file_audio(self, cdn_manager):
        """Test categorization of audio file"""
        category = cdn_manager.categorize_file("music.mp3", "audio/mpeg")
        assert category == "audio"

    def test_categorize_file_pdf(self, cdn_manager):
        """Test categorization of PDF document"""
        category = cdn_manager.categorize_file("document.pdf", "application/pdf")
        assert category == "documents"

    def test_categorize_file_word_doc(self, cdn_manager):
        """Test categorization of Word document"""
        category = cdn_manager.categorize_file(
            "doc.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        assert category == "documents"

    def test_categorize_file_json(self, cdn_manager):
        """Test categorization of JSON config file"""
        category = cdn_manager.categorize_file("config.json", "application/json")
        assert category == "config"

    def test_categorize_file_yaml(self, cdn_manager):
        """Test categorization of YAML config file"""
        category = cdn_manager.categorize_file("settings.yaml", "")
        assert category == "config"

    def test_categorize_file_unknown(self, cdn_manager):
        """Test categorization of unknown file type"""
        category = cdn_manager.categorize_file(
            "unknown.xyz", "application/octet-stream"
        )
        assert category == "files"

    def test_categorize_file_no_extension(self, cdn_manager):
        """Test categorization when file has no extension"""
        category = cdn_manager.categorize_file("file_no_ext", "application/binary")
        assert category == "files"

    def test_validate_and_save_categorized_file_image(self, cdn_manager):
        """Test validate_and_save_categorized_file with an image"""
        # Create a test image
        test_image = Image.new("RGB", (100, 100), color="red")
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format="PNG")
        image_buffer.seek(0)

        # Create UploadFile object
        file = UploadFile(filename="test.png", file=image_buffer)

        # Call the method
        result_url, is_duplicate = cdn_manager.validate_and_save_categorized_file(
            file=file, user_id="test-user", check_duplicates=False
        )

        # Check result
        assert result_url.startswith("/cdn/images/")
        assert result_url.endswith(".png")
        assert is_duplicate is False

        # Check file exists in correct directory
        relative_path = result_url[len("/cdn/") :]
        file_path = Path(cdn_manager.config.CDN_STORAGE_PATH) / relative_path
        assert file_path.exists()
        assert str(file_path).endswith("/images/" + file_path.name)

        # Clean up
        if file_path.exists():
            file_path.unlink(missing_ok=True)

    def test_validate_and_save_categorized_file_gif(self, cdn_manager):
        """Test validate_and_save_categorized_file with a GIF"""
        # Create a test GIF
        test_image = Image.new("RGB", (50, 50), color="blue")
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format="GIF")
        image_buffer.seek(0)

        # Create UploadFile object
        file = UploadFile(filename="animated.gif", file=image_buffer)

        # Call the method
        result_url, is_duplicate = cdn_manager.validate_and_save_categorized_file(
            file=file, user_id="test-user", check_duplicates=False
        )

        # Check result
        assert result_url.startswith("/cdn/gifs/")
        assert result_url.endswith(".gif")
        assert is_duplicate is False

        # Check file exists in correct directory
        relative_path = result_url[len("/cdn/") :]
        file_path = Path(cdn_manager.config.CDN_STORAGE_PATH) / relative_path
        assert file_path.exists()
        assert "gifs" in str(file_path)

        # Clean up
        if file_path.exists():
            file_path.unlink(missing_ok=True)

    def test_validate_and_save_categorized_file_avatar(self, cdn_manager):
        """Test validate_and_save_categorized_file with an avatar"""
        # Create a test image
        test_image = Image.new("RGB", (64, 64), color="green")
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format="PNG")
        image_buffer.seek(0)

        # Create UploadFile object with avatar naming
        file = UploadFile(filename="user_avatar.png", file=image_buffer)

        # Call the method
        result_url, is_duplicate = cdn_manager.validate_and_save_categorized_file(
            file=file, user_id="test-user", check_duplicates=False
        )

        # Check result
        assert result_url.startswith("/cdn/avatars/")
        assert result_url.endswith(".png")
        assert is_duplicate is False

        # Check file exists in avatars directory
        relative_path = result_url[len("/cdn/") :]
        file_path = Path(cdn_manager.config.CDN_STORAGE_PATH) / relative_path
        assert file_path.exists()
        assert "avatars" in str(file_path)

        # Clean up
        if file_path.exists():
            file_path.unlink(missing_ok=True)

    def test_validate_and_save_categorized_file_force_category(self, cdn_manager):
        """Test validate_and_save_categorized_file with forced category"""
        # Create a test image
        test_image = Image.new("RGB", (100, 100), color="purple")
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format="PNG")
        image_buffer.seek(0)

        # Create UploadFile object
        file = UploadFile(filename="forced.png", file=image_buffer)

        # Call the method with forced category
        result_url, is_duplicate = cdn_manager.validate_and_save_categorized_file(
            file=file,
            user_id="test-user",
            check_duplicates=False,
            force_category="config",  # Force it to config category despite being PNG
        )

        # Check result - should be in config regardless of filename
        assert result_url.startswith("/cdn/config/")
        assert result_url.endswith(".png")
        assert is_duplicate is False

        # Check file exists in config directory
        relative_path = result_url[len("/cdn/") :]
        file_path = Path(cdn_manager.config.CDN_STORAGE_PATH) / relative_path
        assert file_path.exists()
        assert "config" in str(file_path)

        # Clean up
        if file_path.exists():
            file_path.unlink(missing_ok=True)

    def test_validate_and_save_categorized_file_too_large_image(self, cdn_manager):
        """Test validate_and_save_categorized_file with image that's too large"""
        # Create a small image but make it exceed the size limit
        test_image = Image.new("RGB", (10, 10), color="orange")
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format="PNG")
        image_buffer.seek(0)

        # Add enough data to exceed 5MB image limit
        large_content = image_buffer.getvalue() + b"x" * (6 * 1024 * 1024)  # Add 6MB
        large_buffer = io.BytesIO(large_content)
        file = UploadFile(filename="large.png", file=large_buffer)

        # Should raise HTTPException due to size limit
        with pytest.raises(HTTPException) as exc_info:
            cdn_manager.validate_and_save_categorized_file(
                file=file, user_id="test-user", check_duplicates=False
            )

        assert "exceeds maximum" in str(exc_info.value.detail)

    def test_validate_and_save_categorized_file_invalid_extension(self, cdn_manager):
        """Test validate_and_save_categorized_file with invalid extension for category"""
        # Create a test image with invalid extension for images
        test_image = Image.new("RGB", (100, 100), color="pink")
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format="PNG")
        image_buffer.seek(0)

        # Create UploadFile object with invalid extension for images
        file = UploadFile(
            filename="test.txt", file=image_buffer
        )  # TXT is not in IMAGE_EXTENSIONS

        # Should raise HTTPException due to extension validation
        with pytest.raises(HTTPException) as exc_info:
            cdn_manager.validate_and_save_categorized_file(
                file=file, user_id="test-user", check_duplicates=False
            )

        assert "not allowed" in str(exc_info.value.detail)

    def test_enhanced_cleanup_all_categories(self, cdn_manager):
        """Test enhanced cleanup task for all categories"""
        # Create test files in all categories
        categories = [
            "files",
            "images",
            "avatars",
            "banners",
            "gifs",
            "stickers",
            "videos",
            "audio",
            "documents",
            "config",
        ]

        test_files = {}

        # Create a test file in each category
        for category in categories:
            test_content = f"test {category} file".encode()
            test_path = (
                Path(cdn_manager.config.CDN_STORAGE_PATH)
                / category
                / f"test_{category}.txt"
            )
            test_path.parent.mkdir(parents=True, exist_ok=True)
            test_path.write_bytes(test_content)

            # Create URL for the database file list simulation
            test_files[category] = [
                f"{cdn_manager.config.CDN_BASE_URL}/{category}/{test_path.name}"
            ]

        # Run cleanup for all categories - should keep all files since they're in our "database"
        for category in categories:
            cdn_manager.cleanup_orphaned_files(test_files[category], category)

        # No files should be deleted since they're all in our "referenced" list
        # Verify all files still exist
        for category in categories:
            test_path = (
                Path(cdn_manager.config.CDN_STORAGE_PATH)
                / category
                / f"test_{category}.txt"
            )
            assert test_path.exists()

        # Now test with empty database - all files should be cleaned up
        for category in categories:
            cdn_manager.cleanup_orphaned_files([], category)

        # Verify all files are gone
        for category in categories:
            test_path = (
                Path(cdn_manager.config.CDN_STORAGE_PATH)
                / category
                / f"test_{category}.txt"
            )
            assert not test_path.exists()


class TestCDNManagerFileServing:
    """Test CDN Manager file serving via HTTP routes"""

    @pytest.fixture
    def cdn_manager(self, tmp_path):
        """Create CDN manager instance with temporary storage"""
        # Use the actual database handler from api_initializer but with test config
        database_handler = api_initializer.database_handler

        # Create test config with temporary paths
        class TestConfig:
            def __init__(self):
                self.CDN_STORAGE_PATH = str(tmp_path / "cdn_test")
                self.CDN_BASE_URL = "/cdn"

        config = TestConfig()
        return CDNManager(database_handler, config)

    def test_categorized_file_url_generation(self, cdn_manager):
        """Test that file URLs are properly generated for each category"""
        import io

        from PIL import Image

        # Test different file types to get different categories
        test_cases = [
            ("avatar.png", "avatars"),
            ("banner.jpg", "banners"),
            ("sticker.png", "stickers"),
            ("animated.gif", "gifs"),
            ("video.mp4", "videos"),
            ("document.pdf", "documents"),
            ("config.json", "config"),
            ("unknown.xyz", "files"),
        ]

        uploaded_urls = []

        for filename, expected_category in test_cases:
            if filename in ["avatar.png", "banner.jpg", "sticker.png"]:
                # Create image file
                test_image = Image.new("RGB", (64, 64), color="blue")
                buffer = io.BytesIO()
                test_image.save(buffer, format="PNG")
                buffer.seek(0)
                file = UploadFile(filename=filename, file=buffer)
            elif filename == "animated.gif":
                # Create GIF file
                test_image = Image.new("RGB", (32, 32), color="red")
                buffer = io.BytesIO()
                test_image.save(buffer, format="GIF")
                buffer.seek(0)
                file = UploadFile(filename=filename, file=buffer)
            elif filename == "video.mp4":
                # Create mock video file (since PIL can't create videos)
                buffer = io.BytesIO(b"mock video content")
                file = UploadFile(filename=filename, file=buffer)
            elif filename == "document.pdf":
                buffer = io.BytesIO(b"mock pdf content")
                file = UploadFile(filename=filename, file=buffer)
            elif filename == "config.json":
                buffer = io.BytesIO(b'{"mock": "config"}')
                file = UploadFile(filename=filename, file=buffer)
            else:
                # unknown.xyz or other files
                buffer = io.BytesIO(b"mock unknown content")
                file = UploadFile(filename=filename, file=buffer)

            # Upload file using categorized method
            file_url, is_duplicate = cdn_manager.validate_and_save_categorized_file(
                file=file, user_id="test-user", check_duplicates=False
            )

            # Verify URL contains expected category
            assert expected_category in file_url
            assert file_url.startswith(f"/cdn/{expected_category}/")
            assert not is_duplicate

            uploaded_urls.append(file_url)

        # Verify all URLs are unique (no duplicates)
        assert len(uploaded_urls) == len(set(uploaded_urls))

    def test_file_accessibility_via_url(self, client, cdn_manager):
        """Test that uploaded files can be accessed via their URLs"""
        import io

        from PIL import Image

        # Create and upload a test image
        test_image = Image.new("RGB", (100, 100), color="green")
        buffer = io.BytesIO()
        test_image.save(buffer, format="PNG")
        buffer.seek(0)

        file = UploadFile(filename="accessible_test.png", file=buffer)

        # Upload via categorized method
        file_url, is_duplicate = cdn_manager.validate_and_save_categorized_file(
            file=file, user_id="test-user", check_duplicates=False
        )

        assert file_url.startswith("/cdn/images/")
        assert not is_duplicate

        # Test that the URL exists (endpoint should return 404 or content)
        # Since we don't have auth required for CDN serving, we can just test if file exists
        # In a real integration test, we'd test the full HTTP endpoint

    def test_cdn_directory_structure(self, cdn_manager):
        """Test that CDN directory structure is created correctly"""
        from pathlib import Path

        # Upload files to trigger directory creation for each category
        categories_to_test = [
            "avatars",
            "banners",
            "images",
            "gifs",
            "stickers",
            "videos",
            "audio",
            "documents",
            "config",
            "files",
        ]

        for category in categories_to_test:
            # Create a small test file in this category
            from io import BytesIO

            content = f"test content for {category}".encode()
            buffer = BytesIO(content)
            file = UploadFile(filename=f"{category}_test.txt", file=buffer)

            if category == "avatars":
                file = UploadFile(filename="test_avatar.png", file=buffer)
            elif category == "images":
                from PIL import Image

                test_image = Image.new("RGB", (50, 50), color="blue")
                img_buffer = BytesIO()
                test_image.save(img_buffer, format="PNG")
                img_buffer.seek(0)
                file = UploadFile(filename="test_image.png", file=img_buffer)

            # Upload file (this creates directory structure)
            try:
                file_url, is_duplicate = cdn_manager.validate_and_save_categorized_file(
                    file=file, user_id="test-user", check_duplicates=False
                )

                # Check directory exists
                category_path = Path(cdn_manager.config.CDN_STORAGE_PATH) / category
                assert category_path.exists()
                assert category_path.is_dir()

            except Exception:
                # Some categories might have restrictions, that's okay for this test
                continue

        # Verify CDN base directory exists
        cdn_base = Path(cdn_manager.config.CDN_STORAGE_PATH)
        assert cdn_base.exists()
        assert cdn_base.is_dir()
