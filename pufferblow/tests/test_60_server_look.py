"""The server's look and welcome message: what the owner may choose, how it is stored and what clients get.

The rules live in ``pufferblow.api.utils.server_look``; the first half tests them directly and the second
half goes through the application, as the owner and as someone who is not.
"""

from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pufferblow.api.utils.server_look import DEFAULT_SERVER_LOOK, ICON_STYLES, ServerLookError, effective_server_look, merge_server_look
from pufferblow.core.bootstrap import api_initializer

# ── the rules ─────────────────────────────────────────────────────


def test_a_server_that_chose_nothing_has_nothing_set():
    assert effective_server_look(None) == DEFAULT_SERVER_LOOK
    assert effective_server_look("damaged") == DEFAULT_SERVER_LOOK


def test_an_update_changes_only_what_it_names_and_null_goes_back_to_derived():
    first = merge_server_look(None, {"icon_style": "bubble", "tone": "sky"})
    second = merge_server_look(first, {"banner_pattern": "burst"})
    assert second == {"icon_style": "bubble", "tone": "sky", "tone2": None, "banner_pattern": "burst"}
    assert merge_server_look(second, {"icon_style": None})["icon_style"] is None


@pytest.mark.parametrize(
    "changes, field",
    [({"icon_style": "star"}, "icon_style"), ({"tone": "neon"}, "tone"), ({"colour": "red"}, "colour"), ({"banner_pattern": 3}, "banner_pattern")],
)
def test_anything_unknown_or_out_of_range_is_refused_by_name(changes, field):
    with pytest.raises(ServerLookError) as raised:
        merge_server_look(None, changes)
    assert raised.value.field == field


def test_the_icon_styles_are_the_four_the_design_names():
    assert ICON_STYLES == ("initials", "crop", "bubble", "school")


# ── through the application ───────────────────────────────────────


def _owner(client: TestClient) -> str:
    user = api_initializer.user_manager.sign_up(username=f"owner_{uuid.uuid4().hex[:6]}", password="12345678", is_owner=True)
    return api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user.user_id), origin_server=user.origin_server)["access_token"]


def _info(client: TestClient) -> dict:
    reply = client.get("/api/v1/system/server-info")
    assert reply.status_code == 200, reply.text
    return reply.json()["server_info"]


def test_the_server_info_carries_the_look_and_it_starts_unset(client: TestClient):
    info = _info(client)
    assert info["look"] == DEFAULT_SERVER_LOOK
    assert "welcome_message" in info and "avatar_kind" in info and "banner_kind" in info


def test_the_owner_saves_a_look_and_everyone_sees_it(client: TestClient):
    token = _owner(client)
    reply = client.put("/api/v1/system/server-appearance", json={"auth_token": token, "look": {"icon_style": "school", "tone": "violet", "banner_pattern": "ripple"}})
    assert reply.status_code == 200, reply.text
    assert reply.json()["look"]["icon_style"] == "school"

    look = _info(client)["look"]  # no token: it is public, like the rest of server-info
    assert look == {"icon_style": "school", "tone": "violet", "tone2": None, "banner_pattern": "ripple"}


def test_a_second_update_keeps_what_the_first_set(client: TestClient):
    token = _owner(client)
    put = lambda look: client.put("/api/v1/system/server-appearance", json={"auth_token": token, "look": look})
    assert put({"tone": "coral"}).status_code == 200
    assert put({"icon_style": "crop"}).status_code == 200
    look = _info(client)["look"]
    assert look["tone"] == "coral" and look["icon_style"] == "crop"


def test_a_bad_look_is_a_400_naming_the_field_and_changes_nothing(client: TestClient):
    token = _owner(client)
    client.put("/api/v1/system/server-appearance", json={"auth_token": token, "look": {"tone": "sage"}})
    reply = client.put("/api/v1/system/server-appearance", json={"auth_token": token, "look": {"tone": "rose", "icon_style": "star"}, "accent_color": "#112233"})
    assert reply.status_code == 400, reply.text
    assert reply.json()["details"]["field"] == "icon_style"
    assert _info(client)["look"]["tone"] == "sage"  # all or nothing


def test_only_someone_who_manages_the_server_can_change_the_look(client: TestClient, account):
    reply = client.put("/api/v1/system/server-appearance", json={"auth_token": account.auth_token, "look": {"tone": "sky"}})
    assert reply.status_code in (401, 403), reply.text
    assert _info(client)["look"] == DEFAULT_SERVER_LOOK


def test_the_welcome_message_is_saved_trimmed_and_limited(client: TestClient):
    token = _owner(client)
    reply = client.put("/api/v1/system/server-info", json={"auth_token": token, "welcome_message": "  Come in, the water is fine  "})
    assert reply.status_code == 200, reply.text
    assert "welcome_message" in reply.json()["updated_fields"]
    assert _info(client)["welcome_message"] == "Come in, the water is fine"

    too_long = client.put("/api/v1/system/server-info", json={"auth_token": token, "welcome_message": "x" * 501})
    assert too_long.status_code == 400
    assert _info(client)["welcome_message"] == "Come in, the water is fine"


def test_renaming_the_server_keeps_the_welcome_message(client: TestClient):
    token = _owner(client)
    client.put("/api/v1/system/server-info", json={"auth_token": token, "welcome_message": "Hello there"})
    client.put("/api/v1/system/server-info", json={"auth_token": token, "server_name": "Renamed"})
    info = _info(client)
    assert info["server_name"] == "Renamed" and info["welcome_message"] == "Hello there"


def test_the_migration_adds_the_column_to_an_older_server_table():
    import sqlalchemy as sa
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    path = Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0007_server_look.py"
    spec = importlib.util.spec_from_file_location("rev0007", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(sa.text("CREATE TABLE server (server_id VARCHAR PRIMARY KEY, server_name VARCHAR)"))
        connection.execute(sa.text("INSERT INTO server VALUES ('s1', 'Home')"))
        with Operations.context(MigrationContext.configure(connection)):
            module.upgrade()
            module.upgrade()  # idempotent
        assert "profile_settings" in {c["name"] for c in sa.inspect(connection).get_columns("server")}
        assert connection.execute(sa.text("SELECT profile_settings FROM server")).scalar() is None
