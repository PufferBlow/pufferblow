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

route = "/api/v1/users/profile"

def test_edit_users_profile(client: TestClient):
    """ Tests the edit a user's profile """
    auth_token = ValueStorage.auth_token

    # Edit username
    data = {
        "auth_token": auth_token,
        "new_username": ValueStorage.new_username
    }

    response = client.put(route, params=data)

    assert response.status_code == 200
    assert response.json() == {
        "status_code": 200,
        "message": "username updated successfully"
    }

    # Edit user's status
    data = {
        "auth_token": auth_token,
        "status": "offline"
    }

    response = client.put(route, params=data)

    assert response.status_code == 200 
    assert response.json() == {
        "status_code": 200,
        "message": "Status updated successfully"
    }

    # Edit user's password
    data = {
        "auth_token": auth_token,
        "old_password": ValueStorage.password,
        "new_password": ValueStorage.new_password
    }

    response = client.put(route, params=data)

    assert response.status_code == 200
    assert response.json() == {
        "status_code": 200,
        "message": "Password updated successfully"
    }

def test_username_already_exists_exception(client: TestClient):
    """ Test the exceptions that will get raise in case the 
    username that we want to change already exists
    """
    data = {
        "auth_token": ValueStorage.auth_token,
        "new_username": ValueStorage.new_username # The same as the one the other test because it will be changed in to it
    }

    response = client.put(route, params=data)

    assert response.status_code == 409
    assert response.json() == {
        "detail": "username already exists. Please change it and try again later"
    }

def test_unvalid_status_value_exception(client: TestClient):
    """ Test the exception that will get raised in case 
    the value of status is neither 'online' or 'offline'
    """
    auth_token = ValueStorage.auth_token
    status = "unvalid"

    data = {
        "auth_token": auth_token,
        "status": status
    }

    response = client.put(route, params=data)

    assert response.status_code == 404
    assert response.json() == {
        "detail": f"status value status='{status}' not found. Accepted values ['online', 'offline']",
    }

def test_users_password_unvalid_exception(client: TestClient):
    """ Test the exception that will get raised in case the user's
    original password wich is `old_password` is not correct
    """
    old_password = "unvalid"

    data = {
        "auth_token": ValueStorage.auth_token,
        "old_password": old_password,
        "new_password": "123456789"
    }

    response = client.put(route, params=data)

    assert response.status_code == 401
    assert response.json() == {
        "detail": "Invalid password. Please try again later."
    }

def test_auth_token_bad_format(client: TestClient):
    """ Tests the exceptions raised when the given auth_token have a bad format """
    data = {
        "auth_token": ValueStorage.bad_formated_auth_token
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
        "status": "online" # As if the request is made to change the user's status
    }

    response = client.put(route, params=data)

    assert response.status_code == 404
    assert response.json() == {
        "detail": "'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
    }
