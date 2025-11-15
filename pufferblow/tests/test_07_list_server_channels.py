from fastapi.testclient import TestClient

from pufferblow.tests.conftest import ValueStorage

route = "/api/v1/channels/list/"


def test_list_server_channels(client: TestClient):
    """Test the list channels route"""
    data = {"auth_token": ValueStorage.auth_token}

    response = client.get(route, params=data)

    assert response.status_code == 200


def test_auth_token_bad_format(client: TestClient):
    """Tests the exceptions raised when the given auth_token have a bad format"""
    data = {"auth_token": ValueStorage.bad_formated_auth_token}

    response = client.get(route, params=data)

    assert response.status_code == 400
    assert response.json() == {
        "error": "Bad auth_token format. Please check your auth_token and try again."
    }


def test_user_not_found(client: TestClient):
    """Tests the exceptions that will get raised due the false auth_token passed"""
    data = {
        "auth_token": ValueStorage.moke_auth_token,
    }

    response = client.get(route, params=data)

    assert response.status_code == 404
    assert response.json() == {
        "error": "'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
    }


def test_empty_auth_token(client: TestClient):
    """Tests pydantic validation for empty auth_token"""
    data = {
        "auth_token": "",
    }

    response = client.get(route, params=data)

    assert response.status_code == 422  # Pydantic validation error
