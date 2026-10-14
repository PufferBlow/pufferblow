"""A user's profile is shown to every signed-in user, so it must never carry credentials."""

from __future__ import annotations

import datetime
import uuid

from pufferblow.api.database.tables.users import Users

SECRETS = ("password", "auth_token", "raw_auth_token")


def test_a_users_dict_has_no_credentials():
    user = Users(
        user_id=uuid.uuid4(),
        username="ada",
        password="$argon2id$hash",
        auth_token="stored-token",
        auth_token_expire_time=datetime.datetime.now(datetime.timezone.utc),
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    user.raw_auth_token = "raw-token"

    shown = user.to_dict()

    for key in SECRETS:
        assert key not in shown
    rendered = repr(shown) + repr(user)
    for secret in ("$argon2id$hash", "stored-token", "raw-token"):
        assert secret not in rendered
    assert shown["username"] == "ada"
