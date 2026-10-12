"""Credentials must never reach the logs."""

import pytest
from loguru import logger

from pufferblow.api.logger.redact import REDACTED, redact
from pufferblow.cli.common import enrich_log_record

JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiI0ODk0YjAwMi1iOGY3LTU1NGMtYTU5NC1kZmE5ZDg0YTM3ZWQifQ."
    "3e1XVTJ1pQ5ohrT0N08yA6jimMwTMUqWqqqa18"
)


@pytest.mark.parametrize(
    "line",
    [
        f'127.0.0.1:62622 - "GET /api/v1/channels/read-history?auth_token={JWT} HTTP/1.1" 200',
        f'127.0.0.1:63744 - "WebSocket /ws?auth_token={JWT}&protocol=1" 403',
        '127.0.0.1:1 - "GET /api/v1/users/signin?username=ada&password=hunter2-secret HTTP/1.1" 200',
        "POST /api/v1/users/profile?refresh_token=abc123def456 HTTP/1.1",
        "PUT /x?old_password=aaa&new_password=bbb&confirm_password=bbb",
        "headers: Authorization: Bearer abcdefghijklmnop.qrstuvwx",
    ],
)
def test_secrets_are_removed_from_access_log_lines(line):
    cleaned = redact(line)
    for secret in (JWT, "hunter2-secret", "abc123def456", "aaa&", "bbb", "abcdefghijklmnop"):
        assert secret not in cleaned
    assert REDACTED in cleaned or "REDACTED" in cleaned


def test_the_rest_of_the_line_is_kept_so_logs_stay_useful():
    cleaned = redact('GET /api/v1/users/list?auth_token=abcdefgh1234&page=2 HTTP/1.1')
    assert cleaned == f"GET /api/v1/users/list?auth_token={REDACTED}&page=2 HTTP/1.1"


def test_bare_tokens_are_found_anywhere_in_the_text():
    assert JWT not in redact(f"AUTH ok token {JWT} accepted")
    assert "pbb_0123456789.abcdefghijklmnopqrstuvwxyz" not in redact(
        "bot pbb_0123456789.abcdefghijklmnopqrstuvwxyz connected"
    )


def test_ordinary_text_is_untouched():
    for text in ("", "Server ready", "user token_count=3 password policy loaded", "GET /api/v1/users/list HTTP/1.1"):
        assert redact(text) == text


def test_the_logging_patcher_redacts_every_sink():
    captured = []
    handler_id = logger.add(lambda message: captured.append(message.record["message"]), level="INFO")
    previous = logger._core.extra  # keep the global config intact for other tests
    try:
        with logger.contextualize():
            patched = logger.patch(enrich_log_record)
            patched.info(f"GET /x?auth_token={JWT} HTTP/1.1")
    finally:
        logger.remove(handler_id)
        logger._core.extra = previous

    assert captured and JWT not in captured[0]
    assert "auth_token=" + REDACTED in captured[0]
