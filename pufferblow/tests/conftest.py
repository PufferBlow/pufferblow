import os
import tempfile
import uuid
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from pufferblow.api.api import api
from pufferblow.core.bootstrap import api_initializer

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
        # Close the pool first: on Windows an open SQLite connection keeps the file from being deleted.
        handler = getattr(api_initializer, "database_handler", None)
        if handler is not None:
            handler.database_engine.dispose()
        if os.path.exists(temp_db.name):
            try:
                os.unlink(temp_db.name)
            except PermissionError:
                pass  # a straggling connection; the temp file is cleaned with the temp directory


@dataclass
class Account:
    """A signed-up user, as the tests need to refer to them."""

    username: str
    password: str
    auth_token: str
    refresh_token: str
    user_id: str


@pytest.fixture
def make_account(client: TestClient):
    """Sign up a fresh user. Every test has its own database, so tests make the accounts they use."""

    def _make(prefix: str = "user", password: str = "12345678") -> Account:
        username = f"{prefix}_{uuid.uuid4().hex[:8]}"
        response = client.post("/api/v1/users/signup", json={"username": username, "password": password})
        assert response.status_code == 201, response.text
        tokens = response.json()
        profile = client.post("/api/v1/users/profile", json={"auth_token": tokens["auth_token"]})
        assert profile.status_code == 200, profile.text
        return Account(username, password, tokens["auth_token"], tokens["refresh_token"], profile.json()["user_data"]["user_id"])

    return _make


@pytest.fixture
def account(make_account) -> Account:
    return make_account()


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
