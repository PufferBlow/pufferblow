import pytest
from fastapi.testclient import TestClient

from pufferblow_api.pufferblow_api import api
from pufferblow_api.tests.conftest import ValueStorage

@pytest.fixture
def client():
    return TestClient(api)

route =  "/api/v1/users/profile"

def test_user_profile(client: TestClient):
    """ Tests the user profile route """
    data = {
        "user_id": ValueStorage.auth_token.split(".")[0],
        "auth_token": ValueStorage.auth_token
    }

    response = client.get(route, params=data)
    response_data = response.json()

    assert response.status_code == 200
    assert response_data["user_data"] # Response contains the data of the user requested

def test_auth_token_bad_format(client: TestClient):
    """ Tests the exceptions raised when the given auth_token have a bad format """
    data = {
        "user_id": ValueStorage.auth_token.split(".")[0],
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
        "user_id": ValueStorage.auth_token.split(".")[0],
        "auth_token": ValueStorage.moke_auth_token
    }

    response = client.get(route, params=data)

    assert response.status_code == 404
    assert response.json() == {
        "detail": "'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
    }

def test_targeted_user_not_found(client: TestClient):
    """ Tests the exceptions that will get raised if the targeted user was not found """
    data = {
        "user_id": ValueStorage.moke_user_id,
        "auth_token": ValueStorage.auth_token
    }

    response = client.get(route, params=data)

    assert response.status_code == 404
    assert response.json() == {
        "detail": f"The target user's user_id='{ValueStorage.moke_user_id}' not found. Please make sure to pass the correct one"
    }
