"""Regression tests for the HTTP Last-Modified helper.

Guards against the v0.0.1-beta bug where a tz-aware-but-non-UTC datetime
(returned by SQLAlchemy reading a Postgres ``TIMESTAMP WITH TIME ZONE``
column on a host whose session time zone wasn't UTC) made
``email.utils.format_datetime(..., usegmt=True)`` raise
``ValueError("usegmt option requires a UTC datetime")``, 500'ing every
avatar / banner / hash-addressed file request.
"""

from datetime import datetime, timedelta, timezone

import pytest

from pufferblow.api.utils.http_datetime import http_last_modified, to_utc


def test_to_utc_naive_assumes_utc():
    naive = datetime(2026, 5, 13, 12, 0, 0)
    converted = to_utc(naive)
    assert converted.tzinfo is timezone.utc
    assert converted.hour == 12  # no shift; treat as UTC, don't reinterpret


def test_to_utc_already_utc_passthrough():
    aware = datetime(2026, 5, 13, 12, 0, 0, tzinfo=timezone.utc)
    converted = to_utc(aware)
    assert converted == aware
    assert converted.utcoffset() == timedelta(0)


def test_to_utc_aware_non_utc_converted():
    plus_two = timezone(timedelta(hours=2))
    aware = datetime(2026, 5, 13, 14, 0, 0, tzinfo=plus_two)
    converted = to_utc(aware)
    assert converted.utcoffset() == timedelta(0)
    assert converted.hour == 12  # 14:00 +02:00 == 12:00 UTC


def test_to_utc_negative_offset_converted():
    minus_five = timezone(timedelta(hours=-5))
    aware = datetime(2026, 5, 13, 7, 0, 0, tzinfo=minus_five)
    converted = to_utc(aware)
    assert converted.utcoffset() == timedelta(0)
    assert converted.hour == 12  # 07:00 -05:00 == 12:00 UTC


@pytest.mark.parametrize(
    "value",
    [
        # The exact shape that triggered the production crash on WSL.
        datetime(2026, 5, 13, 12, 0, 0, tzinfo=timezone(timedelta(hours=2))),
        datetime(2026, 5, 13, 12, 0, 0, tzinfo=timezone(timedelta(hours=-7))),
        datetime(2026, 5, 13, 12, 0, 0, tzinfo=timezone(timedelta(minutes=330))),  # IST
        datetime(2026, 5, 13, 12, 0, 0),  # naive
        datetime(2026, 5, 13, 12, 0, 0, tzinfo=timezone.utc),
    ],
)
def test_http_last_modified_never_raises_on_legal_shapes(value):
    """Any plausible datetime shape produces an RFC 7231 GMT string."""
    rendered = http_last_modified(value)
    assert isinstance(rendered, str)
    assert rendered.endswith(" GMT")


def test_http_last_modified_returns_none_for_none():
    """None passthrough so callers can use it inside conditional assignments."""
    assert http_last_modified(None) is None


def test_http_last_modified_uses_gmt_suffix_not_offset():
    """RFC 7231 mandates the literal `GMT` token, not a numeric offset."""
    rendered = http_last_modified(datetime(2026, 5, 13, 12, 0, 0))
    assert rendered.endswith(" GMT")
    assert "+0000" not in rendered


def test_http_last_modified_idempotent_across_equivalent_inputs():
    """A given instant produces the same string regardless of source zone."""
    naive = datetime(2026, 5, 13, 12, 0, 0)
    aware_utc = datetime(2026, 5, 13, 12, 0, 0, tzinfo=timezone.utc)
    aware_plus_two = datetime(2026, 5, 13, 14, 0, 0, tzinfo=timezone(timedelta(hours=2)))

    a = http_last_modified(naive)
    b = http_last_modified(aware_utc)
    c = http_last_modified(aware_plus_two)
    assert a == b == c
