"""Lightweight SQL injection signature detector for inbound query params.

This is a defence-in-depth layer; the ORM (SQLAlchemy) is the primary
SQL-injection mitigation. The detector exists to flag and rate-limit
clearly-malicious clients (probes scraping for vulns) before they consume
auth or DB resources.

Designed to be conservative: patterns aim for low false-positive rate on
short identifier-shaped params (auth tokens, ids, usernames, channel names).
It will NOT be applied to free-form text bodies — only query-string params on
privileged routes (see ``SecurityMiddleware``).
"""

from __future__ import annotations

import re
from collections.abc import Mapping

# Params whose values can legitimately contain SQL-shaped characters; skip them.
# Passwords in particular may contain quotes, semicolons, comparison operators.
PARAMS_TO_SKIP: frozenset[str] = frozenset(
    {
        "password",
        "old_password",
        "new_password",
    }
)

# Each pattern targets a specific class of injection. Ordered roughly by
# specificity; the first match wins for reporting.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "union_select",
        re.compile(r"\bunion\s+(all\s+)?select\b", re.IGNORECASE),
    ),
    (
        "stacked_statement",
        re.compile(
            r";\s*(drop|delete|insert|update|truncate|alter|create|grant|exec|execute)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "boolean_tautology",
        re.compile(
            r"\b(or|and)\s+(['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?"
            r"|['\"]\w+['\"]?\s*=\s*['\"]?\w*"
            r"|(true|false)\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "time_based",
        re.compile(
            r"\b(sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b",
            re.IGNORECASE,
        ),
    ),
    (
        "information_schema",
        re.compile(r"\binformation_schema\b", re.IGNORECASE),
    ),
    (
        "file_op",
        re.compile(
            r"\b(load_file|into\s+outfile|into\s+dumpfile)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "stored_proc",
        re.compile(r"\b(xp_cmdshell|sp_executesql)\b", re.IGNORECASE),
    ),
    (
        "hex_blob",
        re.compile(r"\b0x[0-9a-f]{16,}\b", re.IGNORECASE),
    ),
    (
        "comment_after_quote",
        re.compile(r"['\"]\s*(--|#|/\*)"),
    ),
)


def detect(value: str) -> str | None:
    """Return the name of the first matching injection pattern, or None.

    Inputs longer than 4 KiB are truncated to bound regex cost on hostile input.
    """
    if not value:
        return None
    sample = value[:4096]
    for name, pattern in _PATTERNS:
        if pattern.search(sample):
            return name
    return None


def detect_in_params(query_params: Mapping[str, str]) -> tuple[str, str] | None:
    """Scan query params for injection signatures.

    Skips entries listed in :data:`PARAMS_TO_SKIP` since those values may
    legitimately contain SQL-shaped characters. Returns ``(param_name,
    pattern_name)`` on first hit, or ``None``.
    """
    for param_name, raw_value in query_params.items():
        if param_name in PARAMS_TO_SKIP:
            continue
        if raw_value is None:
            continue
        hit = detect(str(raw_value))
        if hit is not None:
            return param_name, hit
    return None
