"""Resetting session tokens needs the current password."""

import pytest
from fastapi.testclient import TestClient

route = "/api/v1/users/profile/reset-auth-token"
NOT_A_TOKEN = "abcd"
UNKNOWN_USER_TOKEN = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.apo0widnjtr456yjabmtoa02pgh6547heydbnh1ph"


def test_reset_users_auth_token(client: TestClient, account):
    response = client.post(route, json={"auth_token": account.auth_token, "password": account.password})

    assert response.status_code == 200
    body = response.json()
    assert body["message"] == "auth_token reset successfully"
    assert body["auth_token"] and body["refresh_token"]


def test_password_incorrect_exception(client: TestClient, account):
    response = client.post(route, json={"auth_token": account.auth_token, "password": "not-the-password"})

    assert response.status_code == 403
    body = response.json()
    assert body["error_code"] == "auth.reset_password_wrong"
    assert body["details"]["field"] == "password"


@pytest.mark.parametrize("token", [NOT_A_TOKEN, UNKNOWN_USER_TOKEN])
def test_a_bad_or_unknown_token_is_refused(client: TestClient, token):
    response = client.post(route, json={"auth_token": token, "password": "12345678"})

    assert response.status_code == 401
    assert response.json()["error_code"] == "auth.invalid_token"
