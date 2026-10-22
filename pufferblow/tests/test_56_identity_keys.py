"""Identity keys: validation, registration, lookup and removal."""

from __future__ import annotations

import base64
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from pufferblow.api.identity.keys import InvalidIdentityKey, key_id_of, validate_public_key
from pufferblow.core.bootstrap import api_initializer

URL = "/api/v1/identity-keys"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _new_jwk() -> dict:
    numbers = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": _b64(numbers.x.to_bytes(32, "big")), "y": _b64(numbers.y.to_bytes(32, "big"))}


def _user(name: str):
    user = api_initializer.user_manager.sign_up(username=f"{name}_{uuid.uuid4().hex[:6]}", password="12345678")
    token = api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user.user_id), origin_server=user.origin_server)["access_token"]
    return str(user.user_id), token


def test_a_valid_key_gets_an_id_computed_from_the_key_itself():
    jwk = _new_jwk()
    canonical, key_id = validate_public_key({**jwk, "ext": True, "key_ops": ["verify"]})
    assert canonical == jwk  # extras are dropped, so one key always looks the same
    x = base64.urlsafe_b64decode(jwk["x"] + "==")
    y = base64.urlsafe_b64decode(jwk["y"] + "==")
    assert key_id == key_id_of(x, y) and len(key_id) == 32


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "key",
        {"kty": "RSA"},
        {"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"},
        {"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"},  # wrong size
        {"kty": "EC", "crv": "P-256", "x": "!!!", "y": "!!!"},
        {"kty": "EC", "crv": "P-256", "x": _b64(b"\x01" * 32), "y": _b64(b"\x02" * 32)},  # not on the curve
    ],
)
def test_keys_that_are_not_p256_public_keys_are_refused(bad):
    with pytest.raises(InvalidIdentityKey):
        validate_public_key(bad)


def test_a_private_key_is_refused_rather_than_stored():
    with pytest.raises(InvalidIdentityKey):
        validate_public_key({**_new_jwk(), "d": _b64(b"\x03" * 32)})


def test_register_is_idempotent_and_listing_shows_the_key(client: TestClient):
    user_id, token = _user("ada")
    jwk = _new_jwk()

    first = client.put(URL, json={"auth_token": token, "public_key": jwk, "label": "Laptop"})
    again = client.put(URL, json={"auth_token": token, "public_key": jwk})

    assert first.status_code == 200 and first.json()["created"] is True
    assert again.json()["created"] is False and again.json()["key"]["key_id"] == first.json()["key"]["key_id"]
    _, other_token = _user("grace")
    listed = client.get(f"{URL}/{user_id}", params={"auth_token": other_token}).json()["keys"]  # anyone signed in can read them
    assert [k["key_id"] for k in listed] == [first.json()["key"]["key_id"]]
    assert listed[0]["label"] == "Laptop" and '"kty":"EC"' in listed[0]["public_key"]


def test_a_key_cannot_be_claimed_by_a_second_account(client: TestClient):
    _, first_token = _user("ada")
    _, second_token = _user("grace")
    jwk = _new_jwk()
    assert client.put(URL, json={"auth_token": first_token, "public_key": jwk}).status_code == 200

    stolen = client.put(URL, json={"auth_token": second_token, "public_key": jwk})

    assert stolen.status_code == 409


def test_a_person_can_hold_a_limited_number_of_keys(client: TestClient):
    _, token = _user("ada")
    for _ in range(10):
        assert client.put(URL, json={"auth_token": token, "public_key": _new_jwk()}).status_code == 200
    assert client.put(URL, json={"auth_token": token, "public_key": _new_jwk()}).status_code == 409


def test_only_the_owner_can_remove_a_key(client: TestClient):
    user_id, token = _user("ada")
    _, other_token = _user("grace")
    key_id = client.put(URL, json={"auth_token": token, "public_key": _new_jwk()}).json()["key"]["key_id"]

    assert client.delete(f"{URL}/{key_id}", params={"auth_token": other_token}).status_code == 404
    assert client.delete(f"{URL}/{key_id}", params={"auth_token": token}).status_code == 200
    assert client.get(f"{URL}/{user_id}", params={"auth_token": token}).json()["keys"] == []


def test_the_routes_need_a_signed_in_user(client: TestClient):
    assert client.put(URL, json={"auth_token": "nope", "public_key": _new_jwk()}).status_code in (400, 401)
    assert client.get(f"{URL}/someone", params={"auth_token": "nope"}).status_code in (400, 401)


def test_the_key_id_matches_the_value_the_client_computes():
    # The same vector the client's tests assert against.
    assert key_id_of(bytes(range(32)), bytes(range(32, 64))) == "fdeab9acf3710362bd2658cdc9a29e8f"
