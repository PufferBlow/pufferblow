"""Credentials stay out of URLs, and a password change needs the current password.

Calls the route functions with stubbed managers instead of starting the app (see test_31 for
why the TestClient fixture is avoided).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

import pufferblow.api.routes.users as routes
from pufferblow.api.errors import ApiError, ErrorCode
from pufferblow.api.schemas import EditProfileRequest, SigninQuery


class Users:
    def __init__(self) -> None:
        self.password = "correct horse"
        self.changed_to: str | None = None

    def check_username(self, username):
        return username == "ada"

    def sign_in(self, username, password):
        user = SimpleNamespace(user_id="u-ada", origin_server="x")
        return (user, True, None) if password == self.password else (user, False, "wrong_password")

    def check_user_password(self, user_id, password):
        return password == self.password

    def update_user_password(self, user_id, new_password):
        self.changed_to = new_password


@pytest.fixture
def users(monkeypatch):
    manager = Users()
    initializer = routes.api_initializer
    monkeypatch.setattr(initializer, "user_manager", manager, raising=False)
    monkeypatch.setattr(initializer, "database_handler", SimpleNamespace(create_activity_audit_entry=lambda entry: None), raising=False)
    monkeypatch.setattr(
        initializer,
        "auth_token_manager",
        SimpleNamespace(
            issue_session_tokens=lambda user_id, origin_server: {
                "access_token": "a",
                "refresh_token": "r",
                "token_type": "Bearer",
                "access_token_expires_at": "t1",
                "refresh_token_expires_at": "t2",
            }
        ),
        raising=False,
    )
    monkeypatch.setattr(routes, "get_current_user", lambda token: "u-ada")
    return manager


# ── sign-in ──────────────────────────────────────────────────────


def test_signing_in_with_a_json_body(users):
    response = asyncio.run(routes.signin_user(SigninQuery(username="ada", password="correct horse")))
    assert response["auth_token"] == "a" and response["refresh_token"] == "r"


def test_the_body_route_refuses_bad_credentials_like_the_query_route(users):
    for call in (
        lambda: routes.signin_user(SigninQuery(username="ada", password="nope")),
        lambda: routes.signin_user_with_query(SigninQuery(username="ada", password="nope")),
        lambda: routes.signin_user(SigninQuery(username="nobody", password="x")),
    ):
        with pytest.raises(ApiError) as caught:
            asyncio.run(call())
        assert caught.value.code == ErrorCode.AUTH_INVALID_CREDENTIALS


def test_sign_in_is_a_post_and_the_query_form_is_deprecated():
    signin = [r for r in routes.router.routes if getattr(r, "path", "").endswith("/signin")]
    by_method = {method: route for route in signin for method in route.methods}
    assert "POST" in by_method
    assert by_method["GET"].deprecated is True
