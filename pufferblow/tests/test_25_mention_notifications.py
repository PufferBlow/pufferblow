"""Tests for the mention-extraction helper used by the notifications manager.

Integration tests for the actual delivery chain (send_message route → record
mentions → list/mark-read routes) require the full TestClient fixture which
hangs in this environment; they're scoped to the next test pass. The unit
tests below are sufficient to catch regressions in the mention parser.
"""

import pytest

from pufferblow.api.notifications.notifications_manager import (
    extract_mention_usernames,
)


@pytest.mark.parametrize(
    "content, expected",
    [
        ("hello @alice please look", ["alice"]),
        ("@bob and @carol both", ["bob", "carol"]),
        ("@alice @alice double mention dedupes", ["alice"]),
        ("trailing punctuation @alice.", ["alice"]),
        ("@alice_with_underscore", ["alice_with_underscore"]),
        ("dash-friendly @first-last", ["first-last"]),
        ("dotted @a.b.c", ["a.b.c"]),
        ("hash#@notmention nothing here", []),
        ("ping me at user@example.com (not a mention)", []),
        ("nested @@alice should not match", []),
        ("@", []),
        ("", []),
    ],
)
def test_extract_mention_usernames(content, expected):
    """Extractor returns ordered, deduped usernames; ignores email-like @s."""
    assert extract_mention_usernames(content) == expected


def test_extract_preserves_first_occurrence_order():
    """Order is preserved across multiple mentions of new users."""
    content = "@zara before @amy and again @zara then @bob"
    assert extract_mention_usernames(content) == ["zara", "amy", "bob"]


def test_extract_respects_32_char_cap():
    """Usernames longer than 32 chars match only their first 32 chars."""
    long_name = "a" * 40
    content = f"@{long_name} end"
    extracted = extract_mention_usernames(content)
    assert extracted == ["a" * 32]
