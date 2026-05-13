"""HTTP/RFC 7231 datetime helpers.

The stdlib's :func:`email.utils.format_datetime` with ``usegmt=True`` is
strict: it raises ``ValueError("usegmt option requires a UTC datetime")``
not only for naive datetimes but for ANY tz-aware datetime whose UTC offset
is non-zero. SQLAlchemy reading a Postgres ``TIMESTAMP WITH TIME ZONE``
column can return tz-aware values in the connection's local zone (not UTC),
which makes this trap easy to fall into.

This module centralizes the correct conversion so route handlers can call
one function and not think about it. If you're tempted to call
``format_datetime(..., usegmt=True)`` directly, prefer :func:`http_last_modified`
instead.
"""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import format_datetime


def to_utc(value: datetime) -> datetime:
    """Return ``value`` as a tz-aware UTC datetime.

    - Naive datetime: assume UTC (we always write rows in UTC; the DB just
      sometimes returns them without tz info on certain drivers).
    - Tz-aware datetime in any zone: convert to UTC.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def http_last_modified(value: datetime | None) -> str | None:
    """Render an HTTP ``Last-Modified`` value (RFC 7231 IMF-fixdate).

    Returns ``None`` if ``value`` is ``None`` so callers can use the helper
    inside a conditional dict-assignment without checking twice.

    Example::

        if file_object.created_at:
            cache_headers["Last-Modified"] = http_last_modified(
                file_object.created_at
            )
    """
    if value is None:
        return None
    return format_datetime(to_utc(value), usegmt=True)
