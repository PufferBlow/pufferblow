"""Listing the channels a user can see."""

import pytest
from fastapi.testclient import TestClient

route = "/api/v1/channels/list/"
NOT_A_TOKEN = "abcd"
UNKNOWN_USER_TOKEN = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.apo0widnjtr456yjabmtoa02pgh6547heydbnh1ph"


def test_list_server_channels(client: TestClient, account):
    response = client.post(route, json={"auth_token": account.auth_token})

    assert response.status_code == 200
    assert isinstance(response.json()["channels"], list)


def test_listing_is_a_post_not_a_get(client: TestClient, account):
    assert client.get(route, params={"auth_token": account.auth_token}).status_code == 405


@pytest.mark.parametrize("token", [NOT_A_TOKEN, UNKNOWN_USER_TOKEN])
def test_a_bad_or_unknown_token_is_refused(client: TestClient, token):
    response = client.post(route, json={"auth_token": token})

    assert response.status_code == 401
    assert response.json()["error_code"] == "auth.invalid_token"


def test_empty_auth_token(client: TestClient):
    response = client.post(route, json={"auth_token": ""})

    assert response.status_code == 400
    assert response.json()["error_code"].startswith("validation.")
