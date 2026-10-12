"""Map internal exceptions to safe protocol errors."""

from __future__ import annotations

from fastapi import HTTPException

from pufferblow.api.errors import ApiError
from pufferblow.api.protocol.envelopes import ProtocolErrorCode as Code


class ProtocolError(Exception):
    """Raised by the dispatcher itself (malformed frame, unknown command, ...)."""

    def __init__(self, code: str, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retry_after = retry_after


_STATUS_TO_CODE = {
    400: Code.VALIDATION_FAILED,
    401: Code.UNAUTHENTICATED,
    403: Code.PERMISSION_DENIED,
    404: Code.NOT_FOUND,
    409: Code.CONFLICT,
    413: Code.PAYLOAD_TOO_LARGE,
    422: Code.VALIDATION_FAILED,
    429: Code.RATE_LIMITED,
}

#: What a client is told when something unexpected happens. Nothing internal leaks.
INTERNAL_MESSAGE = "Something went wrong on the server. Try again."


def _code_for_status(status: int) -> str:
    return _STATUS_TO_CODE.get(status, Code.INTERNAL)


def to_wire_error(exc: BaseException) -> tuple[str, str, float | None]:
    """Return ``(code, safe_message, retry_after)`` for an exception.

    Only exceptions the application raises on purpose carry their message to the
    client. Anything else, including database errors, becomes ``INTERNAL``.
    """
    if isinstance(exc, ProtocolError):
        return exc.code, exc.message, exc.retry_after

    if isinstance(exc, ApiError):
        code = _code_for_status(exc.status)
        message = exc.user_message if exc.status < 500 else INTERNAL_MESSAGE
        return code, message, exc.retry_after_seconds

    if isinstance(exc, HTTPException):
        code = _code_for_status(exc.status_code)
        message = str(exc.detail) if exc.status_code < 500 else INTERNAL_MESSAGE
        return code, message, None

    if isinstance(exc, PermissionError):
        return Code.PERMISSION_DENIED, str(exc) or "You are not allowed to do that.", None

    return Code.INTERNAL, INTERNAL_MESSAGE, None
