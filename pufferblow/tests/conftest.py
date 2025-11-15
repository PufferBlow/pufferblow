import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from pufferblow.api.api import api
from pufferblow.api_initializer import api_initializer

# Middlewares


@pytest.fixture(scope="session")
def test_database():
    """Create a temporary database for tests that gets cleaned up after all tests."""
    temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    temp_db.close()

    yield f"sqlite:///{temp_db.name}"

    # Cleanup
    if os.path.exists(temp_db.name):
        os.unlink(temp_db.name)


@pytest.fixture
def client():
    """Test client with isolated database per test."""
    # Create a temporary database for this test
    temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    temp_db.close()

    try:
        # Initialize API with fresh test database
        test_database_uri = f"sqlite:///{temp_db.name}"
        api_initializer.load_objects(database_uri=test_database_uri)

        # Ensure server exists for tests
        if not api_initializer.server_manager.check_server_exists():
            api_initializer.server_manager.create_server(
                server_name="Test Server",
                server_welcome_message="Welcome to the test server!",
            )

        with TestClient(api) as test_client:
            yield test_client
    finally:
        # Cleanup test database
        if os.path.exists(temp_db.name):
            os.unlink(temp_db.name)


# Global storage class
class ValueStorage:
    """
    Value storage class for sharing constants across tests cases
    """

    username: str = "user1"
    password: str = "12345678"
    new_username: str = "new_user1"
    new_password: str = "123456789"
    auth_token: str | None = None
    moke_auth_token: str = (
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.apo0widnjtr456yjabmtoa02pgh6547heydbnh1ph"
    )
    moke_user_id: str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    bad_formated_auth_token: str = "abcd"
