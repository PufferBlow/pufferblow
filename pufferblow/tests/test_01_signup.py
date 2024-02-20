import pytest
from fastapi.testclient import TestClient

from pufferblow.api import api
from pufferblow.tests.conftest import ValueStorage

@pytest.fixture
def client():
    # Use `TestClient` inside a `with` statment
    # to trigger startup/shutdown events
    with TestClient(api) as test_client:
        return test_client

route = "/api/v1/users/signup"

def test_signup(client: TestClient):
    data = {
        "username": ValueStorage.username,
        "password": ValueStorage.password
    }

    response = client.post(route, params=data)

    assert response.status_code == 201
    
    response = response.json()

    ValueStorage.auth_token = response["auth_token"]
    
    print(ValueStorage.auth_token)

def test_signup_username_duplicate_exception(client: TestClient):
    """ Test the exception that will get raised if the username
    used is repeated or duplicated
    """
    data = {
        "username": ValueStorage.username,
        "password": ValueStorage.password
    }

    response = client.post(route, params=data)

    assert response.status_code ==  409
    assert response.json() == {
        "detail": "username already exists. Please change it and try again later",
    }