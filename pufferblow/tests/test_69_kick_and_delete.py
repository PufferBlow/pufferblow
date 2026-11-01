"""Removing someone from a server (their account stays) and deleting your own account (only you can)."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from pufferblow.core.bootstrap import api_initializer

PASSWORD = "12345678"


def _token(user) -> str:
    return api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user.user_id), origin_server=user.origin_server)["access_token"]


def _person(role: str | None = "user", owner: bool = False):
    user = api_initializer.user_manager.sign_up(username=f"p_{uuid.uuid4().hex[:8]}", password=PASSWORD, is_owner=owner)
    if role and not owner:
        api_initializer.database_handler.update_user_roles(str(user.user_id), [role])
    return user, _token(user)


def _kick(client: TestClient, actor_token: str, target) -> "object":
    return client.post(f"/api/v1/server/members/{target.user_id}/kick", json={"auth_token": actor_token})


def _signin(client: TestClient, username: str, password: str = PASSWORD):
    return client.get("/api/v1/users/signin", params={"username": username, "password": password})


def test_a_moderator_removes_a_member_who_keeps_their_account(client: TestClient):
    _, mod = _person("moderator")
    member, member_token = _person()

    reply = _kick(client, mod, member)
    assert reply.status_code == 200, reply.text

    # Their session stops working at once, with an error that says what happened, and they cannot sign in again here.
    refused = client.post("/api/v1/users/profile", json={"auth_token": member_token})
    assert refused.status_code == 403 and refused.json()["error_code"] == "auth.membership_removed"
    signin = _signin(client, member.username)
    assert signin.status_code == 403 and signin.json()["error_code"] == "auth.membership_removed"
    # The account is still there, name and all.
    assert api_initializer.database_handler.get_user(user_id=str(member.user_id)).username == member.username


def test_someone_removed_can_be_let_back_in(client: TestClient):
    _, mod = _person("moderator")
    member, _ = _person()
    _kick(client, mod, member)
    back = client.post(f"/api/v1/server/members/{member.user_id}/reinstate", json={"auth_token": mod})
    assert back.status_code == 200, back.text
    assert _signin(client, member.username).status_code == 200


def test_who_may_remove_whom(client: TestClient):
    owner, owner_token = _person(owner=True)
    mod, mod_token = _person("moderator")
    other_mod, _ = _person("moderator")
    member, member_token = _person()
    target, _ = _person()

    assert _kick(client, member_token, target).status_code == 403  # a member cannot
    assert _kick(client, mod_token, mod).status_code == 400  # not yourself
    assert _kick(client, mod_token, owner).status_code == 403  # never the owner
    assert _kick(client, mod_token, other_mod).status_code == 403  # a moderator cannot remove a moderator
    assert _kick(client, owner_token, other_mod).status_code == 200  # the owner can
    assert _kick(client, mod_token, uuid.uuid4().hex and type("T", (), {"user_id": uuid.uuid4()})()).status_code == 404


def test_you_can_delete_your_own_account_and_what_you_wrote_stays_under_a_ghost_name(client: TestClient):
    person, token = _person()
    name = person.username

    wrong = client.post("/api/v1/users/delete", json={"auth_token": token, "password": "not-the-password"})
    assert wrong.status_code == 401

    reply = client.post("/api/v1/users/delete", json={"auth_token": token, "password": PASSWORD})
    assert reply.status_code == 200, reply.text

    row = api_initializer.database_handler.get_user(user_id=str(person.user_id))
    assert row is not None  # the row stays, so what they wrote keeps its place
    assert row.username.startswith("deleted_") and row.username != name
    assert row.about is None and row.roles_ids == []
    assert _signin(client, name).status_code in (401, 404)  # the name is free and the password is gone
    assert client.post("/api/v1/users/profile", json={"auth_token": token}).status_code in (401, 403)


def test_only_a_current_member_can_be_removed(client: TestClient):
    _, mod = _person("moderator")
    member, _ = _person()
    assert _kick(client, mod, member).status_code == 200
    assert _kick(client, mod, member).status_code == 404  # already removed

    gone, gone_token = _person()
    client.post("/api/v1/users/delete", json={"auth_token": gone_token, "password": PASSWORD})
    assert _kick(client, mod, gone).status_code == 404
    # ...and staff cannot bring an erased account back
    assert client.post(f"/api/v1/server/members/{gone.user_id}/reinstate", json={"auth_token": mod}).status_code == 404
    assert api_initializer.database_handler.get_user(user_id=str(gone.user_id)).membership_status == "deleted"


def test_staff_by_privilege_are_removed_only_by_the_owner(client: TestClient):
    """A custom role that can ban people counts as staff, whatever it is called."""
    _, mod = _person("moderator")
    owner, owner_token = _person(owner=True)
    api_initializer.database_handler.create_role(role_id="warden", role_name="Warden", privileges_ids=["ban_users"])
    warden, _ = _person("warden")
    assert _kick(client, mod, warden).status_code == 403
    assert _kick(client, owner_token, warden).status_code == 200


def test_the_owner_hands_the_server_over_before_deleting(client: TestClient):
    _, owner_token = _person(owner=True)
    reply = client.post("/api/v1/users/delete", json={"auth_token": owner_token, "password": PASSWORD})
    assert reply.status_code == 409 and reply.json()["error_code"] == "account.owner_cannot_delete"


def test_nobody_can_sign_up_as_a_deleted_account(client: TestClient):
    reply = client.post("/api/v1/users/signup", json={"username": "deleted_ab12cd34", "password": PASSWORD})
    assert reply.status_code == 400 and reply.json()["error_code"] == "auth.username_invalid"
    # Renaming is no way round it.
    person, token = _person()
    renamed = client.put("/api/v1/users/profile", json={"auth_token": token, "new_username": "Deleted_user_1"})
    assert renamed.status_code in (400, 422), renamed.text


def test_the_privilege_to_remove_people_is_given_to_moderators_on_existing_servers():
    import sqlalchemy as sa

    from pufferblow.api.database import join_access

    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE privileges (privilege_id TEXT PRIMARY KEY, privilege_name TEXT, category TEXT, created_at TEXT)"))
        conn.execute(sa.text("CREATE TABLE roles (role_id TEXT PRIMARY KEY, privileges_ids TEXT)"))
        conn.execute(sa.text("INSERT INTO privileges VALUES ('ban_users', 'Ban', 'moderation', '2026-01-01')"))
        conn.execute(sa.text("INSERT INTO roles VALUES ('owner', '[]'), ('moderator', '[]'), ('user', '[]')"))
        join_access.apply(conn)
        held = {role: row for role, row in conn.execute(sa.text("SELECT role_id, privileges_ids FROM roles"))}
        assert "kick_users" in held["owner"] and "kick_users" in held["moderator"] and "kick_users" not in held["user"]
        assert conn.execute(sa.text("SELECT COUNT(*) FROM privileges WHERE privilege_id = 'kick_users'")).scalar() == 1
