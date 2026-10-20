"""Editing a profile. One field per request."""

import pytest
from fastapi.testclient import TestClient

route = "/api/v1/users/profile"
NOT_A_TOKEN = "abcd"
UNKNOWN_USER_TOKEN = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.apo0widnjtr456yjabmtoa02pgh6547heydbnh1ph"


def _edit(client, account, **fields):
    return client.put(route, json={"auth_token": account.auth_token, **fields})


def test_edit_username(client: TestClient, account):
    response = _edit(client, account, new_username=f"{account.username}_new")

    assert response.status_code == 200
    assert response.json() == {"status_code": 200, "message": "username updated successfully"}
    profile = client.post(route, json={"auth_token": account.auth_token}).json()["user_data"]
    assert profile["username"] == f"{account.username}_new"


def test_edit_status(client: TestClient, account):
    response = _edit(client, account, status="offline")

    assert response.status_code == 200
    assert response.json()["status"] == "offline"


def test_edit_about(client: TestClient, account):
    assert _edit(client, account, about="hello there").status_code == 200
    assert client.post(route, json={"auth_token": account.auth_token}).json()["user_data"]["about"] == "hello there"


def test_change_password_needs_the_old_one_and_the_new_one_then_works(client: TestClient, account):
    response = _edit(client, account, old_password=account.password, new_password="a-new-password")
    assert response.status_code == 200
    assert response.json()["message"] == "Password updated successfully"

    signin = "/api/v1/users/signin"
    assert client.post(signin, json={"username": account.username, "password": account.password}).status_code == 401
    assert client.post(signin, json={"username": account.username, "password": "a-new-password"}).status_code == 200


def test_username_already_exists_exception(client: TestClient, account, make_account):
    other = make_account("other")

    response = _edit(client, account, new_username=other.username)

    assert response.status_code == 409
    assert response.json()["error_code"] == "auth.username_taken"


def test_unvalid_status_value_exception(client: TestClient, account):
    response = _edit(client, account, status="unvalid")

    assert response.status_code == 422
    assert "online" in response.json()["message"] and "dnd" in response.json()["message"]  # it lists what is accepted


def test_users_password_unvalid_exception(client: TestClient, account):
    response = _edit(client, account, old_password="not-the-password", new_password="123456789")

    assert response.status_code == 403
    assert response.json()["error_code"] == "auth.reset_password_wrong"


@pytest.mark.parametrize("token", [NOT_A_TOKEN, UNKNOWN_USER_TOKEN, ""])
def test_a_bad_or_unknown_token_is_refused(client: TestClient, token):
    response = client.put(route, json={"auth_token": token, "status": "online"})

    assert response.status_code == 401
    assert response.json()["error_code"] == "auth.invalid_token"
