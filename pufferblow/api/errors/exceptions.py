"""``ApiError`` — the one exception any route or manager raises when
something the client should hear about goes wrong.

Use::

    from pufferblow.api.errors import ApiError, ErrorCode
    raise ApiError(ErrorCode.STICKERS_ALIAS_TAKEN, details={"alias": "foo"})

The global exception handler resolves the spec from the registry,
fills the envelope, and emits the response. You can override the
default user-facing message per-raise when you have specific context
to surface::

    raise ApiError(
        ErrorCode.MESSAGES_TOO_LONG,
        user_message=f"Messages on this server can't be longer than {limit} characters.",
        details={"limit": limit, "actual": len(body)},
    )
"""

from __future__ import annotations

from typing import Any


class ApiError(Exception):
    """The canonical raise-from-anywhere error type.

    Carries the ``error_code`` (machine identifier) plus optional
    overrides for the human-facing fields. The global handler does
    the registry lookup and envelope formatting — call sites just
    pick the right code and pass any context-specific details.
    """

    def __init__(
        self,
        code: str,
        *,
        message: str | None = None,
        user_message: str | None = None,
        details: dict[str, Any] | None = None,
        retry_after_seconds: int | None = None,
        status: int | None = None,
    ) -> None:
        """
        Args:
            code: Stable error code from ``ErrorCode``. Required.
            message: Developer / log-oriented message. Falls back to
                the code's registry default. Goes into structured
                logs alongside the request_id.
            user_message: Human-facing override. When None the
                registry default is used (see ``codes.py``).
            details: Optional structured context — field names that
                failed validation, the conflicting alias, the
                attachment size that pushed over the limit. The
                envelope ships this as a flat dict so clients can
                pull values out by key.
            retry_after_seconds: Populated for 429 (and arguably
                503) so clients can honour a backoff hint.
            status: Override the registry-provided status. Almost
                never needed; reserved for cases where one code
                legitimately spans two statuses (e.g. a generic
                NOT_FOUND that the route promotes to 410 GONE).
        """
        # Lazy import to avoid a circular through __init__.py.
        from pufferblow.api.errors.codes import get_error_spec

        spec = get_error_spec(code)
        self.code = code
        self.status = status if status is not None else spec.status
        self.user_message = user_message or spec.user_message
        self.message = message or self.user_message
        self.details = details or {}
        self.retry_after_seconds = retry_after_seconds
        self.retryable = spec.retryable
        super().__init__(self.message)
