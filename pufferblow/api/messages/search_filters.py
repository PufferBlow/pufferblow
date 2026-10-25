"""Filters for message search, the way Discord's search box has them: from, mentions, has, before, after.

A search can carry a text, filters, or both. Filters that the message row answers by itself (who sent it, when)
narrow the rows read; the others (what it contains, what it mentions) are checked on the decrypted message, so
they are applied to what the search finds, not to the whole history.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone

from pufferblow.api.notifications.notifications_manager import extract_mention_usernames

#: What `has:` can ask for.
HAS_TYPES = ("link", "file", "image", "video", "sound", "sticker")
AUTHOR_TYPES = ("user", "bot")

_LINK = re.compile(r"https?://\S+", re.IGNORECASE)


@dataclass(frozen=True)
class SearchFilters:
    from_user_id: str | None = None
    #: A username (as written after `@`), compared ignoring case.
    mentions: str | None = None
    has: tuple[str, ...] = ()
    #: Messages sent strictly before / after these moments (UTC).
    before: datetime | None = None
    after: datetime | None = None
    author_type: str | None = None

    @property
    def active(self) -> bool:
        return any((self.from_user_id, self.mentions, self.has, self.before, self.after, self.author_type))

    @property
    def needs_content(self) -> bool:
        """Whether checking a message means reading its text or attachments, not just its row."""
        return bool(self.mentions or self.has)


def _day(value: str, name: str) -> date:
    try:
        return datetime.fromisoformat(value.strip()).date() if "T" in value else date.fromisoformat(value.strip())
    except ValueError as exc:
        raise ValueError(f"`{name}` must be a date like 2026-03-31.") from exc


def build_filters(
    *,
    from_user_id: str | None = None,
    mentions: str | None = None,
    has: str | None = None,
    before: str | None = None,
    after: str | None = None,
    author_type: str | None = None,
) -> SearchFilters:
    """Check what a client sent and turn it into filters. Raises ``ValueError`` with a message for a bad value."""
    kinds: list[str] = []
    for item in (has or "").split(","):
        item = item.strip().lower()
        if not item:
            continue
        if item not in HAS_TYPES:
            raise ValueError(f"`has` can be one of: {', '.join(HAS_TYPES)}.")
        if item not in kinds:
            kinds.append(item)
    author = (author_type or "").strip().lower() or None
    if author is not None and author not in AUTHOR_TYPES:
        raise ValueError(f"`author_type` can be one of: {', '.join(AUTHOR_TYPES)}.")
    before_at = after_at = None
    if before and before.strip():
        before_at = datetime.combine(_day(before, "before"), time.min, tzinfo=timezone.utc)  # before that day began
    if after and after.strip():
        after_at = datetime.combine(_day(after, "after") + timedelta(days=1), time.min, tzinfo=timezone.utc)  # after that day ended
    if before_at and after_at and after_at > before_at:
        raise ValueError("`after` is later than `before`, so nothing can match.")
    return SearchFilters(
        from_user_id=(from_user_id or "").strip() or None,
        mentions=(mentions or "").strip().lstrip("@").lower() or None,
        has=tuple(kinds),
        before=before_at,
        after=after_at,
        author_type=author,
    )


def _kind(attachment: dict) -> str:
    mime = str(attachment.get("type") or "").lower()
    if mime == "sticker":
        return "sticker"
    if mime.startswith("image/"):
        return "image"
    if mime.startswith("video/"):
        return "video"
    if mime.startswith("audio/"):
        return "sound"
    return "file"


def _when(value) -> datetime | None:
    if isinstance(value, datetime):
        moment = value
    else:
        try:
            moment = datetime.fromisoformat(str(value))
        except (TypeError, ValueError):
            return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def matches(message: dict, filters: SearchFilters) -> bool:
    """Whether a message (as the message manager hydrates it: text, attachments, sender, time) passes the filters."""
    if not filters.active:
        return True
    sender = str(message.get("sender_user_id") or message.get("sender_id") or "")
    is_bot = sender.startswith("bot:")
    if filters.from_user_id and sender != filters.from_user_id:
        return False
    if filters.author_type == "bot" and not is_bot:
        return False
    if filters.author_type == "user" and is_bot:
        return False
    if filters.before or filters.after:
        sent = _when(message.get("sent_at"))
        if sent is None:
            return False
        if filters.before and not sent < filters.before:
            return False
        if filters.after and not sent >= filters.after:
            return False
    text = str(message.get("message") or "")
    if filters.mentions and filters.mentions not in {name.lower() for name in extract_mention_usernames(text)}:
        return False
    if filters.has:
        attachments = [a for a in (message.get("attachments") or []) if isinstance(a, dict)]
        present = {_kind(a) for a in attachments}
        if _LINK.search(text):
            present.add("link")
        if not all(kind in present for kind in filters.has):
            return False
    return True
