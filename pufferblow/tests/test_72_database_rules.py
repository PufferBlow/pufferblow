"""The rules the database enforces (PostgreSQL), as far as they can be tested without it, and how a refusal reaches the person."""

from __future__ import annotations

import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import DBAPIError

from pufferblow.api.database import db_rules
from pufferblow.api.errors.handlers import register_error_handlers


def app_that_fails_with(original: Exception) -> TestClient:
    app = FastAPI()
    register_error_handlers(app)

    @app.get("/boom")
    def boom():
        raise DBAPIError("UPDATE users ...", {}, original)

    return TestClient(app, raise_server_exceptions=False)


def test_a_rule_the_database_enforces_reaches_the_person_as_a_plain_conflict():
    reply = app_that_fails_with(Exception("pufferblow: the last owner cannot be removed. Hand the server over first\nCONTEXT: PL/pgSQL function ...")).get("/boom")
    body = reply.json()
    assert reply.status_code == 409 and body["error_code"] == "state.rule_violated"
    assert body["user_message"] == "The last owner cannot be removed. Hand the server over first."
    assert "PL/pgSQL" not in reply.text  # nothing of the database's own text


def test_any_other_database_error_is_still_a_generic_server_error():
    reply = app_that_fails_with(Exception('relation "users" does not exist')).get("/boom")
    assert reply.status_code == 500 and reply.json()["error_code"] == "server.internal_error"
    assert "relation" not in reply.text


def test_other_databases_are_left_alone():
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        db_rules.apply(connection)


def test_every_rule_says_so_in_words_the_handler_can_find():
    for name, sql in db_rules.FUNCTIONS.items():
        if "RAISE EXCEPTION" in sql:
            assert "RAISE EXCEPTION 'pufferblow: " in sql, name


def test_the_membership_values_the_application_uses_are_allowed():
    assert {"active", "pending", "denied", "remote", "kicked", "deleted"} <= set(db_rules.MEMBERSHIP_VALUES)
