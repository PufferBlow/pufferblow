from fastapi.testclient import TestClient

# Middlewares
from pufferblow.tests.conftest import ValueStorage

# NOTE: The tests won't function now that we have added
# a middleware to handle security. So we need to figure
# a way to fix that.

route = "/api/v1/users/signup"


def test_signup(client: TestClient):
    """Test signup."""
    data = {"username": ValueStorage.username, "password": ValueStorage.password}

    response = client.post(route, json=data)
    response_data = response.json()

    assert response.status_code == 201

    ValueStorage.auth_token = response_data["auth_token"]


def test_signup_username_duplicate_exception(client: TestClient):
    """Test the exception that will get raised if the username
    used is repeated or duplicated
    """
    data = {"username": ValueStorage.username, "password": ValueStorage.password}

    response = client.post(route, json=data)

    assert response.status_code == 409
    assert response.json() == {
        "detail": "username already exists. Please change it and try again later",
    }
