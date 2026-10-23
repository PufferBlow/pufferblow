"""The CLI launch screen: the mono glyph mark picked for the terminal beside a session summary."""

from __future__ import annotations

import io

from pufferblow.cli.glyph import pick_mark, print_splash, render_splash
from pufferblow.cli.glyph_marks import MARKS

SUMMARY = [("command", "serve"), ("platform", "Linux")]


def test_marks_are_the_sheets_sizes_and_stay_in_their_cell_width():
    assert set(MARKS) == {("half", 40), ("half", 26), ("half", 16), ("braille", 24), ("braille", 12), ("braille", 8), ("ascii", 40), ("ascii", 24)}
    for (_, width), rows in MARKS.items():
        assert max(len(r) for r in rows) <= width


def test_the_mark_follows_the_terminal_width():
    assert pick_mark(100, unicode=True) is MARKS[("half", 26)]
    assert pick_mark(64, unicode=True) is MARKS[("half", 26)]
    assert pick_mark(63, unicode=True) is MARKS[("half", 16)]
    assert pick_mark(30, unicode=True) is MARKS[("braille", 8)]
    assert pick_mark(5, unicode=True) is None


def test_a_terminal_without_unicode_gets_the_ascii_mark():
    mark = pick_mark(100, unicode=False)
    assert mark is MARKS[("ascii", 24)]
    assert all(ord(ch) < 128 for row in mark for ch in row)
    assert pick_mark(40, unicode=False) is None


def test_splash_puts_the_summary_beside_the_mark():
    text = render_splash(SUMMARY, version="1.2.3", columns=100)
    lines = text.splitlines()
    assert any("pufferblow  1.2.3" in line for line in lines)
    assert any(line.rstrip().endswith("serve") and "command" in line for line in lines)
    assert len(lines) == len(MARKS[("half", 26)])
    assert "\x1b" not in text  # the mono mark carries no colour codes


def test_splash_without_room_for_a_mark_is_just_the_summary():
    text = render_splash(SUMMARY, version="1.2.3", columns=4)
    assert text.splitlines()[0] == "pufferblow  1.2.3"


def test_colour_only_styles_the_text_not_the_mark():
    text = render_splash(SUMMARY, version="1", columns=100, color=True)
    assert "\x1b[1mpufferblow\x1b[0m" in text
    assert "\x1b" not in text.splitlines()[0]  # the first row is all mark


def test_print_splash_picks_ascii_for_a_stream_that_is_not_utf8():
    class Latin1(io.StringIO):
        encoding = "cp1252"

    out = Latin1()
    print_splash(SUMMARY, version="1", stream=out)
    assert all(ord(ch) < 128 for ch in out.getvalue())
