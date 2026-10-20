"""Sign-up."""

import uuid

import pytest
from fastapi.testclient import TestClient

route = "/api/v1/users/signup"


def test_signup(client: TestClient):
    response = client.post(route, json={"username": f"user_{uuid.uuid4().hex[:8]}", "password": "12345678"})

    assert response.status_code == 201
    body = response.json()
    assert body["auth_token"] and body["refresh_token"] and body["token_type"]


def test_the_new_account_can_use_its_token_straight_away(client: TestClient, account):
    response = client.post("/api/v1/users/profile", json={"auth_token": account.auth_token})
    assert response.status_code == 200
    assert response.json()["user_data"]["username"] == account.username


def test_signup_username_duplicate_exception(client: TestClient):
    """A name already taken is refused, however often it is tried."""
    data = {"username": f"duplicate_{uuid.uuid4().hex[:8]}", "password": "12345678"}

    assert client.post(route, json=data).status_code == 201
    response = client.post(route, json=data)

    assert response.status_code == 409
    assert response.json()["error_code"] == "auth.username_taken"


def test_a_short_password_is_refused_and_says_why(client: TestClient):
    response = client.post(route, json={"username": f"user_{uuid.uuid4().hex[:8]}", "password": "1"})

    assert response.status_code == 400
    body = response.json()
    assert body["error_code"] == "auth.password_too_weak"
    assert body["details"]["field"] == "password"


@pytest.mark.parametrize("name", ["everyone", "Everyone", " everyone "])
def test_the_everyone_mention_cannot_be_a_username(client: TestClient, name: str):
    response = client.post(route, json={"username": name, "password": "12345678"})
    assert response.status_code == 400
    assert response.json()["error_code"] == "auth.username_invalid"
