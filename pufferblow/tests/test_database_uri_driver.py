"""A bare ``postgresql://`` address must not leave the driver to SQLAlchemy (psycopg 3 is the driver this project installs)."""

import pytest

from pufferblow.api.config.config_handler import with_driver


@pytest.mark.parametrize(
    "given, expected",
    [
        ("postgresql://u:p@db:5432/x", "postgresql+psycopg://u:p@db:5432/x"),
        ("postgres://u:p@db/x", "postgresql+psycopg://u:p@db/x"),
        ("postgresql+psycopg2://u:p@db/x", "postgresql+psycopg://u:p@db/x"),
        ("postgresql+psycopg://u:p@db/x", "postgresql+psycopg://u:p@db/x"),
        ("postgresql+asyncpg://u:p@db/x", "postgresql+asyncpg://u:p@db/x"),
        ("sqlite:///x.db", "sqlite:///x.db"),
    ],
)
def test_with_driver(given, expected):
    assert with_driver(given) == expected
