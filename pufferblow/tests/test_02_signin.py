"""Sign-in. The password goes in a JSON body; the query form is deprecated."""

import pytest
from fastapi.testclient import TestClient

route = "/api/v1/users/signin"


def test_user_signin(client: TestClient, account):
    response = client.post(route, json={"username": account.username, "password": account.password})

    assert response.status_code == 200
    assert response.json()["auth_token"]


def test_the_deprecated_query_form_still_works(client: TestClient, account):
    response = client.get(route, params={"username": account.username, "password": account.password})
    assert response.status_code == 200


def test_username_not_found(client: TestClient):
    """An unknown name and a wrong password give the same answer, so a name cannot be probed for."""
    response = client.post(route, json={"username": "nobody_here", "password": "12345678"})

    assert response.status_code == 401
    assert response.json()["error_code"] == "auth.invalid_credentials"


def test_password_is_incorrect(client: TestClient, account):
    response = client.post(route, json={"username": account.username, "password": "not-the-password"})

    assert response.status_code == 401
    assert response.json()["error_code"] == "auth.invalid_credentials"


def test_unknown_user_and_wrong_password_are_indistinguishable(client: TestClient, account):
    unknown = client.post(route, json={"username": "nobody_here", "password": "12345678"}).json()
    wrong = client.post(route, json={"username": account.username, "password": "not-the-password"}).json()
    assert unknown["user_message"] == wrong["user_message"]
    assert unknown["error_code"] == wrong["error_code"]


@pytest.mark.parametrize("body", [{"username": "", "password": "x"}, {"username": "someone", "password": ""}])
def test_empty_fields_fail_validation(client: TestClient, body):
    response = client.post(route, json=body)

    assert response.status_code == 400
    assert response.json()["error_code"].startswith("validation.")
