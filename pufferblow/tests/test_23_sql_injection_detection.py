"""Tests for SQL injection pattern detection in query parameters."""

import pytest
from fastapi.testclient import TestClient

from pufferblow.api.security import sql_injection_detector


# --- Detector unit tests ------------------------------------------------------


@pytest.mark.parametrize(
    "payload, expected_pattern",
    [
        ("1' UNION SELECT password FROM users--", "union_select"),
        ("a'; DROP TABLE users; --", "stacked_statement"),
        ("admin' OR 1=1--", "boolean_tautology"),
        ("' OR 'a'='a", "boolean_tautology"),
        ("'; WAITFOR DELAY '0:0:5'--", "time_based"),
        ("1' AND SLEEP(5)--", "time_based"),
        ("' UNION SELECT * FROM information_schema.tables--", "union_select"),
        ("test' UNION SELECT LOAD_FILE('/etc/passwd')--", "union_select"),
        ("'; EXEC xp_cmdshell('whoami')--", "stacked_statement"),
        ("0x4142434445464748494a4b4c4d4e4f50", "hex_blob"),
        ("foo' --", "comment_after_quote"),
        ("foo'/*bar*/", "comment_after_quote"),
    ],
)
def test_detect_flags_known_injection_patterns(payload, expected_pattern):
    """Each known injection signature should be flagged with its expected pattern."""
    assert sql_injection_detector.detect(payload) == expected_pattern


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "alice",
        "alice@example.com",
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.apo0widnjtr456yjabmtoa02pgh6547heydbnh1ph",
        "general-chat",
        "My channel name (v2)",
        "Hello, world! 1 + 1 = 2.",
        "online",
    ],
)
def test_detect_does_not_flag_benign_values(payload):
    """Identifier-shaped values should not trip the detector."""
    assert sql_injection_detector.detect(payload) is None


def test_detect_in_params_skips_password_fields():
    """Password params can legitimately contain SQL-shaped characters."""
    params = {"password": "' OR 1=1 -- I picked a bad password"}
    assert sql_injection_detector.detect_in_params(params) is None


def test_detect_in_params_returns_param_name_and_pattern():
    """A hit on a non-skipped param surfaces both the param name and pattern."""
    params = {
        "auth_token": "abcd-1234' UNION SELECT 1--",
        "page": "1",
    }
    hit = sql_injection_detector.detect_in_params(params)
    assert hit == ("auth_token", "union_select")


def test_detect_truncates_very_long_input():
    """Inputs over 4 KiB should be truncated; a clean prefix means no hit."""
    benign_prefix = "a" * 4096
    payload = benign_prefix + "' UNION SELECT 1--"
    # Pattern appears after the 4096 boundary, so detection should miss it.
    assert sql_injection_detector.detect(payload) is None


# --- Middleware integration tests ---------------------------------------------

privileged_route = "/api/v1/users/list"


def test_middleware_rejects_injection_in_query_param(client: TestClient):
    """Injection signatures in query params on privileged routes return 400."""
    response = client.get(
        privileged_route,
        params={"auth_token": "abcd' UNION SELECT 1 FROM users--"},
    )
    assert response.status_code == 400
    assert response.json() == {
        "error": "Request rejected: query parameter contains a disallowed pattern."
    }


def test_middleware_blocks_ip_after_repeated_injection(client: TestClient):
    """Crossing SQL_INJECTION_BLOCK_THRESHOLD adds the IP to BlockedIPS."""
    payload = {"auth_token": "abcd' OR 1=1--"}

    # First two attempts → 400 each.
    for _ in range(2):
        resp = client.get(privileged_route, params=payload)
        assert resp.status_code == 400

    # Third attempt crosses the threshold and the IP is blocked.
    resp = client.get(privileged_route, params=payload)
    assert resp.status_code == 403
    assert "blocked" in resp.json()["message"].lower()
