"""Who may come in: the one rule both a new account and someone joining with their existing account go through.

``open`` lets anyone in. ``invite`` needs a valid invitation code. ``request`` asks the owner or a moderator, unless the
person has a valid code, which is as good as being let in. Keeping this in one place is what stops "sign up on the
page" from being a way round a private server.
"""

from __future__ import annotations

from pufferblow.api.errors import ApiError, ErrorCode

ACTIVE = "active"
PENDING = "pending"


class JoinPolicy:
    def __init__(self, database_handler) -> None:
        self.database = database_handler

    def mode(self) -> str:
        return self.database.get_join_mode()

    def admit(self, invite_code: str | None) -> str:
        """``active`` (let in; a code, if used, is now spent) or ``pending`` (wait for a decision). Raises when a code is needed or wrong."""
        mode = self.mode()
        if mode == "open":
            return ACTIVE
        code = (invite_code or "").strip()
        if code:
            # A wrong code is refused the same way whatever is wrong with it, so codes cannot be guessed one fact at a time.
            if self.database.redeem_invite(code):
                return ACTIVE
            raise ApiError(ErrorCode.JOIN_INVITE_INVALID)
        if mode == "invite":
            raise ApiError(ErrorCode.JOIN_INVITE_REQUIRED)
        return PENDING
