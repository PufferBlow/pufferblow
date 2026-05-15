"""Retry helper for transient database connection drops.

The SQLAlchemy engine is already configured with ``pool_pre_ping=True``,
which validates each connection on checkout. But that only catches
already-dead connections at the START of a session — it can't help if
Postgres (or an intermediate firewall / NAT / cloud LB) drops the TCP
connection MID-query. The next query in that session raises::

    psycopg2.OperationalError: server closed the connection unexpectedly

That's recoverable: by the time we retry, ``pool_pre_ping`` plus the
invalidation SQLAlchemy did on the failed checkout means the next
session gets a fresh, healthy connection from a freshly-opened TCP
socket.

**Use this only for read-only operations.** Wrapping a mutation in a
retry can double-execute writes if the connection drop happened
*after* the row was committed but before the response landed. Read
paths (channel list, user profile, settings reads) are safe.
"""

from __future__ import annotations

from typing import Callable, TypeVar

from loguru import logger
from sqlalchemy.exc import DisconnectionError, OperationalError

_T = TypeVar("_T")

# Errors we treat as "the connection died, retrying is safe."
# OperationalError covers "server closed the connection unexpectedly,"
# "could not receive data from server," and similar transport failures.
# DisconnectionError is SQLAlchemy's own signal that the pool detected
# a bad connection and invalidated it.
_RECOVERABLE = (OperationalError, DisconnectionError)


def read_with_retry(
    operation: Callable[[], _T],
    *,
    retries: int = 1,
    label: str | None = None,
) -> _T:
    """Run a read-only DB ``operation``, retrying once on a transport drop.

    Args:
        operation: A zero-arg callable that performs the read.
        retries: How many extra attempts on top of the first try.
            Default 1 means "try, then retry once on transport error."
        label: Optional human label included in the warning log so an
            operator can correlate the retry with a specific route.

    Returns:
        The operation's return value.

    Raises:
        The original exception when ``retries`` are exhausted.
    """
    attempts = max(1, retries + 1)
    last_exc: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            return operation()
        except _RECOVERABLE as exc:
            last_exc = exc
            # The error message from psycopg2 is multi-line and includes
            # the full SQL. Only the first line is useful in a log entry;
            # the rest is rendered when whoever cares pulls the traceback.
            first_line = str(exc).split("\n", 1)[0]
            if attempt < attempts:
                logger.warning(
                    "db_retry: transient drop on attempt {attempt}/{total}"
                    "{label_part} — retrying. err={err}",
                    attempt=attempt,
                    total=attempts,
                    label_part=f" [{label}]" if label else "",
                    err=first_line,
                )
            else:
                logger.error(
                    "db_retry: exhausted {total} attempts{label_part} — "
                    "giving up. err={err}",
                    total=attempts,
                    label_part=f" [{label}]" if label else "",
                    err=first_line,
                )

    assert last_exc is not None  # unreachable: loop runs at least once
    raise last_exc
