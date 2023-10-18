import pytest
from fastapi.testclient import TestClient

from pufferblow_api.pufferblow_api import api
from pufferblow_api.tests.conftest import ValueStorage

@pytest.fixture
def client():
    # Use `TestClient` inside a `with` statment
    # to trigger startup/shutdown events
    with TestClient(api) as test_client:
        return test_client
route = "/api/v1/users/list"

def test_list_users(client: TestClient):
    """ Test the list users route """
    data = {
        "auth_token": ValueStorage.auth_token
    }

    response = client.get(route, params=data)

    assert response.status_code == 200

def test_auth_token_bad_format(client: TestClient):
    """ Tests the exceptions raised when the given auth_token have a bad format """
    data = {
        "auth_token": ValueStorage.bad_formated_auth_token
    }

    response = client.get(route, params=data)

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Bad auth_token format. Please check your auth_token and try again."
    }

def test_user_not_found(client: TestClient):
    """ Tests the exceptions that will get raised due the false auth_token passed """
    data = {
        "auth_token": ValueStorage.moke_auth_token,
    }

    response = client.get(route, params=data)

    assert response.status_code == 404
    assert response.json() == {
        "detail": "'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
    }
