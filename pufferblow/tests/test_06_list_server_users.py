"""Listing the instance's users."""

import pytest
from fastapi.testclient import TestClient

route = "/api/v1/users/list"
NOT_A_TOKEN = "abcd"
UNKNOWN_USER_TOKEN = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.apo0widnjtr456yjabmtoa02pgh6547heydbnh1ph"


def test_list_users(client: TestClient, account, make_account):
    other = make_account("other")

    response = client.get(route, params={"auth_token": account.auth_token})

    assert response.status_code == 200
    text = response.text
    assert account.username in text and other.username in text
    for secret in ("password", "raw_auth_token"):
        assert secret not in text


@pytest.mark.parametrize("token", [NOT_A_TOKEN, UNKNOWN_USER_TOKEN])
def test_a_token_that_is_not_one_is_refused(client: TestClient, token):
    response = client.get(route, params={"auth_token": token})

    assert response.status_code == 400
    assert "auth_token" in response.json()["error"]


def test_empty_auth_token(client: TestClient):
    assert client.get(route, params={"auth_token": ""}).status_code == 422  # fails validation
