"""The launch screen: the Pufferblow glyph mark beside a short session summary.

Follows the Terminal Glyph sheet's splash, in its mono marks. The mark is plain text in the
terminal's own foreground colour (no colour codes), so it reads on any theme and survives being
piped into a log. The size and style are picked from what the terminal can show:

- 64 columns or more: the 26-cell half-block mark beside the summary.
- Down to 40 columns: the 16-cell half-block mark.
- Narrower: the 8-cell braille mark, which fits a status bar.
- A terminal that cannot show Unicode (a legacy Windows code page, ``LANG=C``, CI): the ASCII mark.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import TextIO

from pufferblow.cli.glyph_marks import MARKS

# The sheet's launch screen needs this many columns for the 26-cell mark; below it, the 16-cell one.
FULL_SPLASH_COLUMNS = 64
GAP = 4


def _speaks_unicode(stream: TextIO) -> bool:
    encoding = (getattr(stream, "encoding", None) or "").lower().replace("_", "-")
    return encoding.startswith("utf")


# (style, width, columns the terminal needs). The large marks sit beside the summary, the smallest alone.
_UNICODE_MARKS = (("half", 26, FULL_SPLASH_COLUMNS), ("half", 16, 44), ("braille", 8, 8))
_ASCII_MARKS = (("ascii", 24, 52),)


def pick_mark(columns: int, *, unicode: bool) -> tuple[str, ...] | None:
    """The mark that fits `columns`, or None when not even the smallest does."""
    for style, width, needed in _UNICODE_MARKS if unicode else _ASCII_MARKS:
        if columns >= needed:
            return MARKS[(style, width)]
    return None


def _styled(text: str, code: str, enabled: bool) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if enabled else text


def render_splash(
    summary: list[tuple[str, str]],
    *,
    name: str = "pufferblow",
    version: str = "",
    columns: int | None = None,
    unicode: bool = True,
    color: bool = False,
) -> str:
    """The mark on the left, the name and `summary` (label, value rows) on the right."""
    columns = columns if columns is not None else shutil.get_terminal_size((80, 24)).columns
    mark = pick_mark(columns, unicode=unicode)

    label_width = max((len(label) for label, _ in summary), default=0) + 2
    head = _styled(name, "1", color) + (f"  {version}" if version else "")
    text = [head, ""] + [f"{_styled(label.ljust(label_width), '2', color)}{value}" for label, value in summary]

    if mark is None:
        return "\n".join([head] + [f"{label.ljust(label_width)}{value}" for label, value in summary]) + "\n"

    width = max(len(row) for row in mark)
    top = max(0, (len(mark) - len(text)) // 2)
    rows = []
    for i in range(max(len(mark), top + len(text))):
        left = (mark[i] if i < len(mark) else "").ljust(width)
        right = text[i - top] if 0 <= i - top < len(text) else ""
        rows.append((left + " " * GAP + right).rstrip())
    return "\n".join(rows) + "\n"


def print_splash(summary: list[tuple[str, str]], *, version: str = "", stream: TextIO | None = None) -> None:
    """Writes the launch screen for the terminal behind `stream` (stdout by default)."""
    stream = stream or sys.stdout
    is_tty = hasattr(stream, "isatty") and stream.isatty()
    columns = shutil.get_terminal_size((80, 24)).columns if is_tty else 80
    text = render_splash(
        summary,
        version=version,
        columns=columns,
        unicode=_speaks_unicode(stream),
        color=is_tty and "NO_COLOR" not in os.environ,
    )
    stream.write(text)
    stream.flush()
