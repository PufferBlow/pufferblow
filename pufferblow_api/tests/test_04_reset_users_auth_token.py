import pytest
from fastapi.testclient import TestClient

from pufferblow_api.pufferblow_api import api
from pufferblow_api.tests.conftest import ValueStorage

@pytest.fixture
def client():
    return TestClient(api)

route = "/api/v1/users/profile/reset-auth-token"

def test_reset_users_auth_token(client: TestClient):
    """ Tests the functionallity to reset a user's auth_token """
    data = {
        "auth_token": ValueStorage.auth_token,
        "password": ValueStorage.new_password # Because the password got changed in the last test
    }

    response = client.put(route, params=data)

    assert response.status_code == 200
    assert response.json()["message"] == "auth_token rested successfully" and response.json()["auth_token"]

    ValueStorage.auth_token = response.json()["auth_token"] # Changing the auth_token into the new one

def test_user_is_suspended_exception(client: TestClient):
    """ Test the exceptions that will get raised in case
    the user is suspended from reseting their auth_token
    """
    data = {
        "auth_token": ValueStorage.auth_token,
        "password": ValueStorage.new_password # Because the password got changed in the last test
    }

    response = client.put(route, params=data)

    assert response.status_code == 403
    assert response.json() == {
        "detail": "Cannot reset authentication token. Suspension time has not elapsed."
    }

def test_password_incorrect_exception(client: TestClient):
    """ Test the exception that will get raised in case 
    the password is not correct
    """
    data = {
        "auth_token": ValueStorage.auth_token,
        "password": ValueStorage.password # The old password the we have changed in test number #3
    }

    response = client.put(route, params=data)

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Incorrect password. Please try again"
    }

def test_auth_token_bad_format(client: TestClient):
    """ Tests the exceptions raised when the given auth_token have a bad format """
    data = {
        "auth_token": ValueStorage.bad_formated_auth_token,
        "password": ValueStorage.new_password
    }

    response = client.put(route, params=data)

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Bad auth_token format. Please check your auth_token and try again."
    }

def test_user_not_found(client: TestClient):
    """ Tests the exceptions that will get raised due the false auth_token passed """
    data = {
        "auth_token": ValueStorage.moke_auth_token,
        "password": ValueStorage.new_password
    }

    response = client.put(route, params=data)

    assert response.status_code == 404
    assert response.json() == {
        "detail": "'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
    }
