import pytest
from fastapi.testclient import TestClient

from pufferblow_api.pufferblow_api import api
from pufferblow_api.tests.conftest import ValueStorage

@pytest.fixture
def client():
    return TestClient(api)

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
