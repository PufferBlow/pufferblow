"""Reading a profile."""

import pytest
from fastapi.testclient import TestClient

route = "/api/v1/users/profile"
NOT_A_TOKEN = "abcd"
UNKNOWN_USER_TOKEN = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.apo0widnjtr456yjabmtoa02pgh6547heydbnh1ph"
NOBODY = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def test_user_profile(client: TestClient, account):
    response = client.post(route, json={"auth_token": account.auth_token, "user_id": account.user_id})

    assert response.status_code == 200
    data = response.json()["user_data"]
    assert data["username"] == account.username and data["user_id"] == account.user_id


def test_without_a_user_id_it_is_your_own_profile(client: TestClient, account):
    assert client.post(route, json={"auth_token": account.auth_token}).json()["user_data"]["user_id"] == account.user_id


def test_someone_else_s_profile_is_readable_and_has_no_credentials(client: TestClient, account, make_account):
    other = make_account("other")

    data = client.post(route, json={"auth_token": account.auth_token, "user_id": other.user_id}).json()["user_data"]

    assert data["username"] == other.username
    for secret in ("password", "auth_token", "raw_auth_token"):
        assert secret not in data


def test_a_new_account_has_default_art_in_its_profile(client: TestClient, account):
    data = client.post(route, json={"auth_token": account.auth_token}).json()["user_data"]
    assert data["avatar_url"].startswith("/assets/avatars/") and data["banner_url"].startswith("/assets/banners/")


@pytest.mark.parametrize("token", [NOT_A_TOKEN, UNKNOWN_USER_TOKEN])
def test_a_bad_or_unknown_token_is_refused(client: TestClient, token):
    response = client.post(route, json={"auth_token": token})

    assert response.status_code == 401
    assert response.json()["error_code"] == "auth.invalid_token"


@pytest.mark.parametrize("target", [NOBODY, "not-an-id"])
def test_targeted_user_not_found(client: TestClient, account, target):
    """Asking for someone who does not exist is a 404, not a crash."""
    response = client.post(route, json={"auth_token": account.auth_token, "user_id": target})

    assert response.status_code == 404
    assert response.json()["error_code"] == "resource.not_found"


def test_empty_auth_token(client: TestClient):
    response = client.post(route, json={"auth_token": ""})

    assert response.status_code == 400
    assert response.json()["error_code"].startswith("validation.")
