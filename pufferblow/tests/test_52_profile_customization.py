"""Profile customisation: pronouns, a custom status, and the settings object (frame, colours, theme...).

The rules live in ``pufferblow.api.utils.profile_settings``; the first half tests them directly and the
second half goes through the application. Every option is a choice from a short list, and an update is
all-or-nothing.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pufferblow.api.utils.profile_settings import (
    ABOUT_MAX,
    CUSTOM_STATUS_MAX,
    DEFAULT_PROFILE_SETTINGS,
    PRONOUNS_MAX,
    ProfileSettingsError,
    check_text_length,
    effective_profile_settings,
    merge_profile_settings,
)

# ── the rules ─────────────────────────────────────────────────────


def test_a_person_who_chose_nothing_has_the_defaults():
    assert effective_profile_settings(None) == DEFAULT_PROFILE_SETTINGS
    assert effective_profile_settings({}) == DEFAULT_PROFILE_SETTINGS
    assert effective_profile_settings("not an object") == DEFAULT_PROFILE_SETTINGS  # a damaged value never leaks out


def test_defaults_are_a_copy_nobody_can_change():
    mine = effective_profile_settings(None)
    mine["sections"]["play"] = False
    assert DEFAULT_PROFILE_SETTINGS["sections"]["play"] is True


def test_an_update_changes_only_what_it_names():
    first = merge_profile_settings(None, {"frame": "spines", "tone": "violet"})
    second = merge_profile_settings(first, {"card_theme": "duo", "tone2": "sky"})
    assert second["frame"] == "spines" and second["tone"] == "violet"  # kept
    assert second["card_theme"] == "duo" and second["tone2"] == "sky"  # added


def test_sections_are_switched_one_at_a_time():
    result = merge_profile_settings(None, {"sections": {"accounts": True}})
    assert result["sections"] == {"play": True, "mains": True, "accounts": True, "badges": True}


def test_the_face_colour_and_pattern_can_go_back_to_the_ones_derived_from_the_handle():
    chosen = merge_profile_settings(None, {"expression": "wink", "tone": "coral", "banner_pattern": "duo"})
    assert chosen["expression"] == "wink" and chosen["banner_pattern"] == "duo"
    back = merge_profile_settings(chosen, {"expression": None, "tone": None, "banner_pattern": None})
    assert back["expression"] is None and back["tone"] is None and back["banner_pattern"] is None


@pytest.mark.parametrize(
    "changes, field",
    [
        ({"frame": "flames"}, "frame"),  # not in the list
        ({"tone": "#ff0000"}, "tone"),  # colours are names, never free hex values
        ({"card_theme": "solid"}, "card_theme"),  # not one of mono / tinted / duo
        ({"card_theme": None}, "card_theme"),  # only the face, the colours and the pattern may be null
        ({"expression": "furious"}, "expression"),
        ({"name_font": "mono"}, "name_font"),
        ({"name_font": "comic sans"}, "name_font"),
        ({"motion": "spin"}, "motion"),
        ({"unknown": 1}, "unknown"),  # not stored: the column is not a place for arbitrary data
        ({"sections": {"secret": True}}, "sections.secret"),
        ({"sections": {"play": "yes"}}, "sections.play"),
        ({"sections": "all"}, "sections"),
        ({"frame": 3}, "frame"),
    ],
)
def test_anything_outside_the_lists_is_refused_and_names_the_field(changes, field):
    with pytest.raises(ProfileSettingsError) as caught:
        merge_profile_settings(None, changes)
    assert caught.value.field == field


def test_one_bad_value_refuses_the_whole_update():
    current = {"frame": "ring"}
    with pytest.raises(ProfileSettingsError):
        merge_profile_settings(current, {"frame": "spines", "tone": "nope"})
    assert current == {"frame": "ring"}  # the input is untouched


def test_the_settings_must_be_an_object():
    for bad in ("frame", ["frame"], 3, True):
        with pytest.raises(ProfileSettingsError):
            merge_profile_settings(None, bad)


def test_text_is_trimmed_and_limited():
    assert check_text_length("about", "  hi  ", ABOUT_MAX) == "hi"
    assert check_text_length("about", "x" * ABOUT_MAX, ABOUT_MAX)
    with pytest.raises(ProfileSettingsError):
        check_text_length("about", "x" * (ABOUT_MAX + 1), ABOUT_MAX)


# ── through the application ───────────────────────────────────────


def _profile(client: TestClient, token: str) -> dict:
    reply = client.post("/api/v1/users/profile", json={"auth_token": token})
    assert reply.status_code == 200, reply.text
    return reply.json()["user_data"]


def test_a_new_profile_shows_the_defaults_and_no_text(client: TestClient, account):
    profile = _profile(client, account.auth_token)
    assert profile["pronouns"] is None and profile["custom_status"] is None
    assert profile["profile_settings"] == DEFAULT_PROFILE_SETTINGS


def test_settings_are_saved_and_come_back_in_the_profile_and_the_list(client: TestClient, account):
    reply = client.put(
        "/api/v1/users/profile/appearance",
        json={"auth_token": account.auth_token, "profile_settings": {"frame": "bubbles", "tone": "sage", "sections": {"accounts": True}}},
    )
    assert reply.status_code == 200, reply.text
    assert reply.json()["profile_settings"]["frame"] == "bubbles"

    mine = _profile(client, account.auth_token)["profile_settings"]
    assert mine["frame"] == "bubbles" and mine["tone"] == "sage" and mine["sections"]["accounts"] is True
    assert mine["card_theme"] == "mono"  # untouched

    listed = client.get("/api/v1/users/list", params={"auth_token": account.auth_token}).json()["users"]
    assert next(u for u in listed if u["username"] == account.username)["profile_settings"]["frame"] == "bubbles"


def test_a_second_update_keeps_what_the_first_set(client: TestClient, account):
    put = lambda settings: client.put("/api/v1/users/profile/appearance", json={"auth_token": account.auth_token, "profile_settings": settings})
    assert put({"frame": "ring"}).status_code == 200
    assert put({"motion": "still"}).status_code == 200
    settings = _profile(client, account.auth_token)["profile_settings"]
    assert settings["frame"] == "ring" and settings["motion"] == "still"


def test_a_bad_setting_is_a_400_that_names_the_field_and_changes_nothing(client: TestClient, account):
    client.put("/api/v1/users/profile/appearance", json={"auth_token": account.auth_token, "profile_settings": {"frame": "ring"}})

    reply = client.put(
        "/api/v1/users/profile/appearance",
        json={"auth_token": account.auth_token, "profile_settings": {"frame": "spines", "tone": "neon"}, "accent_color": "#112233"},
    )

    assert reply.status_code == 400, reply.text
    assert reply.json()["details"]["field"] == "tone" and reply.json()["error_code"] == "validation.field_range"
    profile = _profile(client, account.auth_token)
    assert profile["profile_settings"]["frame"] == "ring"  # not "spines": all or nothing
    assert profile["accent_color"] != "#112233"


def test_settings_cannot_be_set_for_somebody_else(client: TestClient, make_account):
    ada, bo = make_account("ada"), make_account("bo")
    client.put("/api/v1/users/profile/appearance", json={"auth_token": ada.auth_token, "profile_settings": {"frame": "spines"}})
    assert _profile(client, bo.auth_token)["profile_settings"]["frame"] == "none"


def test_pronouns_and_a_custom_status_are_saved_trimmed_and_can_be_cleared(client: TestClient, account):
    reply = client.put("/api/v1/users/profile", json={"auth_token": account.auth_token, "pronouns": "  she/her ", "custom_status": "grinding to Phantom"})
    assert reply.status_code == 200, reply.text
    profile = _profile(client, account.auth_token)
    assert profile["pronouns"] == "she/her" and profile["custom_status"] == "grinding to Phantom"

    client.put("/api/v1/users/profile", json={"auth_token": account.auth_token, "custom_status": ""})
    profile = _profile(client, account.auth_token)
    assert profile["custom_status"] is None and profile["pronouns"] == "she/her"  # only the one was cleared


@pytest.mark.parametrize(
    "field, limit",
    [("pronouns", PRONOUNS_MAX), ("custom_status", CUSTOM_STATUS_MAX), ("about", ABOUT_MAX)],
)
def test_text_over_the_limit_is_refused_with_the_limit(client: TestClient, account, field, limit):
    ok = client.put("/api/v1/users/profile", json={"auth_token": account.auth_token, field: "x" * limit})
    assert ok.status_code == 200, ok.text

    refused = client.put("/api/v1/users/profile", json={"auth_token": account.auth_token, field: "x" * (limit + 1)})

    assert refused.status_code == 400, refused.text
    details = refused.json()["details"]
    assert details["field"] == field and details["max"] == limit


def test_the_migration_adds_the_columns_to_an_older_users_table():
    """A database from before this change gets the three columns, and running it again is harmless."""
    import importlib.util
    from pathlib import Path

    import sqlalchemy as sa
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    path = Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0005_profile_customization.py"
    spec = importlib.util.spec_from_file_location("rev0005", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(sa.text("CREATE TABLE users (user_id VARCHAR PRIMARY KEY, username VARCHAR)"))
        with Operations.context(MigrationContext.configure(connection)):
            module.upgrade()
            module.upgrade()  # idempotent
        columns = {c["name"] for c in sa.inspect(connection).get_columns("users")}
    assert {"pronouns", "custom_status", "profile_settings"} <= columns
