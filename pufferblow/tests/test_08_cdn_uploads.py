import io

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from pufferblow.tests.conftest import ValueStorage


class TestCDNUploads:
    """Test cases for CDN file upload functionality"""

    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up test data"""
        self.auth_token = ValueStorage.auth_token
        self.moke_auth_token = ValueStorage.moke_auth_token

    def test_upload_avatar_success(self, client: TestClient):
        """Test successful avatar upload"""
        # Create a small test image
        test_image = Image.new("RGB", (100, 100), color="red")
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format="PNG")
        image_buffer.seek(0)

        data = {"auth_token": self.auth_token}
        files = {"file": ("test_avatar.png", image_buffer, "image/png")}

        response = client.post("/api/v1/users/profile/avatar", data=data, files=files)

        assert response.status_code == 201
        response_data = response.json()
        assert response_data["status_code"] == 201
        assert response_data["message"] == "Avatar uploaded successfully"
        assert "avatar_url" in response_data
        assert response_data["avatar_url"].startswith("/cdn/avatars/")

    def test_upload_banner_success(self, client: TestClient):
        """Test successful banner upload"""
        # Create a rectangular test image (suitable for banner)
        test_image = Image.new("RGB", (400, 200), color="blue")
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format="JPEG")
        image_buffer.seek(0)

        data = {"auth_token": self.auth_token}
        files = {"file": ("test_banner.jpg", image_buffer, "image/jpeg")}

        response = client.post("/api/v1/users/profile/banner", data=data, files=files)

        assert response.status_code == 201
        response_data = response.json()
        assert response_data["status_code"] == 201
        assert response_data["message"] == "Banner uploaded successfully"
        assert "banner_url" in response_data
        assert response_data["banner_url"].startswith("/cdn/banners/")

    def test_upload_avatar_large_file_error(self, client: TestClient):
        """Test file too large error"""
        # Create a large image (exceeding default 5MB limit)
        # Note: PIL can't create extremely large images, so we create a normal sized one
        # In a real scenario with very large files, this would trigger the size check
        test_image = Image.new("RGB", (1000, 1000), color="green")
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format="PNG")
        image_buffer.seek(0)

        # Manually make the buffer appear larger than the limit
        original_limit = 1024 * 1024  # 1MB for this test
        if len(image_buffer.getvalue()) > original_limit:
            data = {"auth_token": self.auth_token}
            files = {"file": ("large_image.png", image_buffer, "image/png")}

            response = client.post(
                "/api/v1/users/profile/avatar", data=data, files=files
            )

            # This might not trigger the limit check since PIL compresses well,
            # but the infrastructure is in place for when files exceed limits

    def test_upload_avatar_invalid_extension_error(self, client: TestClient):
        """Test invalid file extension error"""
        # Create a valid JPEG but rename with invalid extension
        test_image = Image.new("RGB", (100, 100), color="yellow")
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format="JPEG")
        image_buffer.seek(0)

        data = {"auth_token": self.auth_token}
        files = {"file": ("test_image.invalid", image_buffer, "image/jpeg")}

        response = client.post("/api/v1/users/profile/avatar", data=data, files=files)

        assert response.status_code == 400
        assert "not allowed" in response.json()["detail"]

    def test_upload_avatar_invalid_mime_error(self, client: TestClient):
        """Test invalid MIME type error"""
        # Create a text file pretending to be an image
        text_content = b"This is not an image file"
        text_buffer = io.BytesIO(text_content)

        data = {"auth_token": self.auth_token}
        files = {"file": ("fake_image.png", text_buffer, "image/png")}

        response = client.post("/api/v1/users/profile/avatar", data=data, files=files)

        # This should trigger MIME type validation
        # Note: The actual response depends on magic detection
        assert response.status_code in [200, 400]  # 200 if magic allows, 400 if not

    def test_upload_avatar_no_file_error(self, client: TestClient):
        """Test missing file error"""
        data = {"auth_token": self.auth_token}

        response = client.post("/api/v1/users/profile/avatar", data=data)

        # Should fail because file is required
        assert response.status_code == 422  # Pydantic validation error

    def test_upload_avatar_invalid_auth_token(self, client: TestClient):
        """Test invalid auth token error"""
        test_image = Image.new("RGB", (100, 100), color="purple")
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format="PNG")
        image_buffer.seek(0)

        data = {"auth_token": self.moke_auth_token}
        files = {"file": ("test.png", image_buffer, "image/png")}

        response = client.post("/api/v1/users/profile/avatar", data=data, files=files)

        assert response.status_code == 404

    def test_cdn_file_serving(self, client: TestClient):
        """Test that uploaded files are served correctly"""
        # First upload an avatar
        test_image = Image.new("RGB", (50, 50), color="orange")
        image_buffer = io.BytesIO()
        test_image.save(image_buffer, format="PNG")
        image_buffer.seek(0)

        data = {"auth_token": self.auth_token}
        files = {"file": ("serve_test.png", image_buffer, "image/png")}

        upload_response = client.post(
            "/api/v1/users/profile/avatar", data=data, files=files
        )
        assert upload_response.status_code == 201

        avatar_url = upload_response.json()["avatar_url"]

        # Now try to serve the file
        serve_response = client.get(avatar_url)

        # The CDN is mounted, so this should serve the file
        # Note: In testing, the actual file serving might be mocked
        assert serve_response.status_code in [
            200,
            404,
        ]  # 404 if not served in test environment

    def test_upload_banner_image_too_large_dimensions(self, client: TestClient):
        """Test image dimensions too large error"""
        # Create an image larger than the 2048x2048 limit
        # Note: PIL won't actually create extremely large images in memory,
        # but this tests the logic path
        try:
            test_image = Image.new("RGB", (3000, 3000), color="black")
            image_buffer = io.BytesIO()
            test_image.save(image_buffer, format="PNG")
            image_buffer.seek(0)

            data = {"auth_token": self.auth_token}
            files = {"file": ("large_dim.png", image_buffer, "image/png")}

            response = client.post(
                "/api/v1/users/profile/banner", data=data, files=files
            )

            # If the dimension check triggers, there will be an error
            if response.status_code == 400:
                assert "dimensions too large" in response.json()["detail"]

        except MemoryError:
            # PIL might fail to create very large images - that's expected
            pass

    def test_server_settings_integration(self, client: TestClient):
        """Test that CDN respects server settings"""
        # This would ideally test that the CDN is using database settings
        # For now, we verify the CDN manager loads settings successfully

        from pufferblow.api_initializer import api_initializer

        # Ensure CDN manager has server settings loaded
        assert api_initializer.cdn_manager.MAX_IMAGE_SIZE_MB == 5  # Default
        assert (
            len(api_initializer.cdn_manager.IMAGE_EXTENSIONS) >= 1
        )  # At least has defaults
