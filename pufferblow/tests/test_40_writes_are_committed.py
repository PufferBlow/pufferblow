"""Writes that used to be lost: `database_session()` is a plain sessionmaker, so a block that
changes rows without `session.commit()` is rolled back when it closes.

Each test reads the row back in a fresh session, which is what a later request sees. Builds a
DatabaseHandler against a throwaway SQLite file (see test_31 for why the TestClient fixture is
avoided).
"""

from __future__ import annotations

import datetime
import os
import tempfile
import uuid

import pytest
import sqlalchemy

from pufferblow.api.database.database_handler import DatabaseHandler
from pufferblow.api.database.tables.notification_preferences import NotificationPreferences
from pufferblow.api.database.tables.notifications import Notifications
from pufferblow.api.database.tables.users import Users
from pufferblow.api.encrypt.encrypt import Encrypt
from pufferblow.api.models.config_model import Config


@pytest.fixture
def db():
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp.close()
    engine = sqlalchemy.create_engine(f"sqlite:///{tmp.name}")
    handler = DatabaseHandler(database_engine=engine, encrypt_manager=Encrypt(), config=Config())
    yield handler
    handler.database_engine.dispose()
    try:
        if os.path.exists(tmp.name):
            os.unlink(tmp.name)
    except PermissionError:
        pass


def _fresh(db, model, **where):
    with db.database_session() as session:
        return session.query(model).filter_by(**where).one_or_none()


def test_marking_a_notification_read_is_saved(db):
    user_id = str(uuid.uuid4())
    notification_id = str(uuid.uuid4())
    db.create_notification(
        Notifications(
            notification_id=notification_id,
            user_id=user_id,
            type="mention",
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
    )

    assert db.mark_notification_read(notification_id, user_id) is True

    assert _fresh(db, Notifications, notification_id=notification_id).read_at is not None
    assert db.mark_notification_read(notification_id, user_id) is False  # already read


def test_a_notification_preference_is_saved_and_updated(db):
    user_id = str(uuid.uuid4())

    db.upsert_notification_preference(user_id=user_id, channel_id="c1", muted=True, mention_only=False)
    stored = _fresh(db, NotificationPreferences, user_id=user_id, channel_id="c1")
    assert stored is not None and stored.muted is True

    db.upsert_notification_preference(user_id=user_id, channel_id="c1", muted=False, mention_only=True)
    stored = _fresh(db, NotificationPreferences, user_id=user_id, channel_id="c1")
    assert (stored.muted, stored.mention_only) == (False, True)


def test_the_appearance_backfill_is_saved(db):
    user_id = uuid.uuid4()
    with db.database_session() as session:
        session.add(
            Users(
                user_id=user_id,
                username="ada",
                password="x",
                about="",
                status="online",
                auth_token="t",
                auth_token_expire_time=datetime.datetime.now(datetime.timezone.utc),
                created_at=datetime.datetime.now(datetime.timezone.utc),
                accent_color=None,
                avatar_seed=None,
            )
        )
        session.commit()

    db._backfill_appearance_defaults()

    stored = _fresh(db, Users, user_id=user_id)
    assert stored.accent_color and stored.avatar_seed == str(user_id)
