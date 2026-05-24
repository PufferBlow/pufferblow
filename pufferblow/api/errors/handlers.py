"""Global FastAPI exception handlers — every error response goes
through here so the envelope is consistent regardless of which layer
raised.

Five handlers are wired:

  1. ``ApiError`` (the canonical, code-aware shape).
  2. ``HTTPException`` (FastAPI / Starlette) — auto-mapped via
     status code + heuristics to the closest registry entry.
     Keeps the 60+ existing ``HTTPException`` call sites working
     on the new envelope without an immediate manual migration.
  3. ``RequestValidationError`` (Pydantic body / query / form
     validation) — flattened into ``validation.field_*`` codes
     with per-field details so the client can highlight the
     specific input.
  4. ``FriendsError`` / ``StickersError`` — legacy manager
     exceptions that still leak through some routes. Mapped onto
     the appropriate ``friends.*`` / ``stickers.*`` codes.
  5. ``Exception`` (catch-all) — last-resort handler. Logs with
     full traceback + request_id, returns a generic
     ``server.internal_error`` envelope so the user gets a useful
     message rather than a 500 HTML page.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from loguru import logger

from pufferblow.api.errors.codes import ErrorCode, get_error_spec
from pufferblow.api.errors.exceptions import ApiError


def _request_id(request: Request) -> str | None:
    """Pull the request_id stashed by ``request_logging_middleware``.

    Returns None when the middleware hasn't run yet (e.g. during
    startup-time exceptions) so the envelope falls back gracefully
    rather than crashing the handler.
    """
    return getattr(getattr(request, "state", None), "request_id", None)


def _envelope(
    *,
    request: Request,
    code: str,
    status: int,
    message: str,
    user_message: str,
    details: dict[str, Any] | None = None,
    retry_after_seconds: int | None = None,
) -> JSONResponse:
    """Build the wire-format error envelope.

    Wire shape is the documented contract — see ``docs/ERROR_CODES.md``.
    Keep the field set stable; new optional fields are non-breaking,
    renames or removals require a deprecation cycle.
    """
    payload: dict[str, Any] = {
        "status_code": status,
        "error_code": code,
        "message": message,
        "user_message": user_message,
        "details": details or {},
        "request_id": _request_id(request),
        "retry_after_seconds": retry_after_seconds,
    }
    headers: dict[str, str] = {}
    if retry_after_seconds is not None:
        # Honor the HTTP semantic too — well-behaved clients
        # (curl, browsers, load balancers) will already respect
        # Retry-After without needing to parse our envelope.
        headers["Retry-After"] = str(retry_after_seconds)
    return JSONResponse(status_code=status, content=payload, headers=headers)


# ── ApiError ─────────────────────────────────────────────────────
async def _handle_api_error(request: Request, exc: ApiError) -> JSONResponse:
    """The well-typed path. The exception already carries everything
    the envelope needs; we just unwrap and serialise.
    """
    # 5xx errors get a structured log so operators can correlate by
    # request_id when a user reports a problem. 4xx errors are by
    # definition the client's fault, so we don't pollute logs with
    # them at INFO level (the request_logging_middleware already
    # emits a WARNING line on the exit log).
    if exc.status >= 500:
        logger.bind(
            request_id=_request_id(request),
            error_code=exc.code,
        ).error(f"API error {exc.code}: {exc.message}")

    return _envelope(
        request=request,
        code=exc.code,
        status=exc.status,
        message=exc.message,
        user_message=exc.user_message,
        details=exc.details,
        retry_after_seconds=exc.retry_after_seconds,
    )


# ── HTTPException ─────────────────────────────────────────────────
#
# FastAPI / Starlette routes still raise plain HTTPException in many
# places. We translate by status code + body heuristics so the new
# envelope ships everywhere without a Big-Bang migration. New code
# should prefer ``ApiError`` directly because it preserves the code
# verbatim instead of inferring from status.

# Map HTTP status → fallback error_code. Used when no other signal
# is available. Each line is a curated default that matches the
# most common reason a route would raise that status.
_STATUS_FALLBACK = {
    400: ErrorCode.VALIDATION_PAYLOAD_MALFORMED,
    401: ErrorCode.AUTH_INVALID_TOKEN,
    403: ErrorCode.AUTH_PRIVILEGE_DENIED,
    404: ErrorCode.RESOURCE_NOT_FOUND,
    409: ErrorCode.RESOURCE_CONFLICT,
    413: ErrorCode.VALIDATION_PAYLOAD_TOO_LARGE,
    422: ErrorCode.VALIDATION_FIELD_TYPE,
    429: ErrorCode.RATE_LIMIT_EXCEEDED,
    500: ErrorCode.SERVER_INTERNAL_ERROR,
    503: ErrorCode.SERVER_UNAVAILABLE,
}


async def _handle_http_exception(request: Request, exc: HTTPException) -> JSONResponse:
    """Translate the long-tail of legacy HTTPException raises.

    Auth dependencies still raise ``HTTPException(401, "...")`` and a
    pile of routes follow the same pattern. Until they migrate to
    ``ApiError``, this handler does its best to pick the right code:

      * If the detail string is a registry message verbatim, we can
        reverse-look it up — but we don't try; routes word their
        messages freely and that match would be flaky.
      * Status code is the strongest signal; map to a sensible
        default code from ``_STATUS_FALLBACK``.
      * The detail string (when present and a plain string, not a
        Pydantic-validation array) becomes the user message — these
        messages are already written by humans for humans, so
        passing them through is the right call.

    The envelope ``message`` field is the same as ``user_message``
    in this path because we don't have a separate dev-message
    available. That's fine — log noise comes from the
    request_logging_middleware exit line.
    """
    fallback_code = _STATUS_FALLBACK.get(exc.status_code, ErrorCode.SERVER_INTERNAL_ERROR)
    spec = get_error_spec(fallback_code)

    # detail can be: a string (the common case), a dict (rarely —
    # some routes pass {"message": "..."}), or a list (FastAPI's
    # validation handler — but RequestValidationError has its own
    # path, so this is the rarer case where a route built its own
    # list manually). We handle all three by coercing to a single
    # human-readable string.
    raw_detail = exc.detail
    detail_message: str
    detail_payload: dict[str, Any] = {}
    if isinstance(raw_detail, str):
        detail_message = raw_detail
    elif isinstance(raw_detail, dict):
        detail_message = str(raw_detail.get("message") or raw_detail.get("detail") or raw_detail)
        # Carry through extra context (e.g. retry_after_seconds the
        # rate-limit middleware embedded). Skip the message key.
        detail_payload = {k: v for k, v in raw_detail.items() if k not in ("message", "detail")}
    else:
        detail_message = str(raw_detail) if raw_detail else spec.user_message

    user_message = detail_message or spec.user_message
    retry_after = detail_payload.pop("retry_after_seconds", None) if detail_payload else None

    # 5xx logging mirrors the ApiError handler.
    if exc.status_code >= 500:
        logger.bind(
            request_id=_request_id(request),
            error_code=fallback_code,
        ).error(f"HTTPException {exc.status_code}: {detail_message}")

    return _envelope(
        request=request,
        code=fallback_code,
        status=exc.status_code,
        message=detail_message,
        user_message=user_message,
        details=detail_payload or None,
        retry_after_seconds=retry_after,
    )


# ── RequestValidationError (Pydantic) ─────────────────────────────
async def _handle_validation_error(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Flatten Pydantic's validation array into our envelope.

    FastAPI's default emits a 422 with ``detail: [{loc, msg, type}]``
    — useful to a developer reading the JSON, lousy as a toast. We
    normalise each entry into ``details.fields`` and pick a single
    representative ``validation.field_*`` code based on the first
    error's type. Most validation failures are missing-or-wrong-type
    on a single field; the field-level entries in ``details`` cover
    the multi-field case for clients that want to highlight inputs.
    """
    raw_errors = exc.errors()
    fields: list[dict[str, Any]] = []
    for err in raw_errors:
        loc = err.get("loc", ())
        # loc is a tuple like ('body', 'username'); strip the source
        # prefix because the client cares about the field name.
        field_name = ".".join(str(p) for p in loc[1:]) if len(loc) > 1 else (
            str(loc[0]) if loc else "<unknown>"
        )
        fields.append({
            "field": field_name,
            "type": err.get("type", "unknown"),
            "message": err.get("msg", "invalid value"),
        })

    # Pick the headline code from the first error's type. ``missing``
    # → field_required; numeric range → field_range; everything else
    # collapses to field_type. The full list lives in details for
    # clients that want it.
    first_type = (raw_errors[0].get("type") if raw_errors else "") or ""
    if first_type == "missing" or first_type.endswith("required"):
        code = ErrorCode.VALIDATION_FIELD_REQUIRED
    elif "greater_than" in first_type or "less_than" in first_type or "length" in first_type:
        code = ErrorCode.VALIDATION_FIELD_RANGE
    elif "value_error" in first_type and "json" in (raw_errors[0].get("msg") or "").lower():
        code = ErrorCode.VALIDATION_PAYLOAD_MALFORMED
    else:
        code = ErrorCode.VALIDATION_FIELD_TYPE

    spec = get_error_spec(code)
    # Build a user-friendly headline. Single field gets its own
    # message; multi-field collapses to "Some fields need attention."
    if len(fields) == 1:
        user_message = (
            f"{spec.user_message} ({fields[0]['field']})"
            if fields[0]["field"] != "<unknown>"
            else spec.user_message
        )
    else:
        user_message = spec.user_message

    return _envelope(
        request=request,
        code=code,
        status=spec.status,
        message=f"Validation failed on {len(fields)} field(s).",
        user_message=user_message,
        details={"fields": fields},
    )


# ── Domain exceptions ─────────────────────────────────────────────
async def _handle_friends_error(request: Request, exc) -> JSONResponse:  # type: ignore[no-untyped-def]
    """``FriendsError`` from the friends manager. Mapped onto the
    closest ``friends.*`` code based on the manager's status_code.
    Until the manager itself migrates to ``ApiError``, this handler
    keeps the envelope shape correct.
    """
    # Status_code attribute carries the intent the manager wanted.
    status = getattr(exc, "status_code", 400)
    message = str(exc)
    if "self" in message.lower():
        code = ErrorCode.FRIENDS_SELF_RELATION
    elif "block" in message.lower():
        code = ErrorCode.FRIENDS_BLOCKED
    elif status == 404:
        code = ErrorCode.FRIENDS_NOT_FOUND
    elif status == 409 or "duplicate" in message.lower() or "exists" in message.lower():
        code = ErrorCode.FRIENDS_DUPLICATE_REQUEST
    elif status == 403:
        code = ErrorCode.FRIENDS_NOT_RECIPIENT
    else:
        code = ErrorCode.RESOURCE_CONFLICT

    spec = get_error_spec(code)
    return _envelope(
        request=request,
        code=code,
        status=spec.status,
        message=message,
        user_message=message or spec.user_message,
    )


async def _handle_stickers_error(request: Request, exc) -> JSONResponse:  # type: ignore[no-untyped-def]
    """``StickersError`` → ``stickers.*`` envelope. Same heuristic
    shape as ``_handle_friends_error``.
    """
    status = getattr(exc, "status_code", 400)
    message = str(exc)
    msg_lower = message.lower()
    if "alias" in msg_lower and ("take" in msg_lower or "use" in msg_lower):
        code = ErrorCode.STICKERS_ALIAS_TAKEN
    elif "alias" in msg_lower:
        code = ErrorCode.STICKERS_INVALID_ALIAS
    elif "display_name" in msg_lower or "display name" in msg_lower:
        code = ErrorCode.STICKERS_INVALID_DISPLAY_NAME
    elif "unsupported" in msg_lower or "type" in msg_lower:
        code = ErrorCode.STICKERS_UNSUPPORTED_TYPE
    elif "too large" in msg_lower or status == 413:
        code = ErrorCode.STICKERS_TOO_LARGE
    elif status == 404:
        code = ErrorCode.STICKERS_NOT_FOUND
    else:
        code = ErrorCode.STICKERS_NOT_AVAILABLE

    spec = get_error_spec(code)
    return _envelope(
        request=request,
        code=code,
        status=spec.status,
        message=message,
        user_message=message or spec.user_message,
    )


# ── Catch-all ─────────────────────────────────────────────────────
async def _handle_unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
    """Last-resort handler.

    Logs with full traceback and emits a generic
    ``server.internal_error`` envelope. The ``request_id`` in the
    response is the key a user pastes when reporting the problem —
    it joins the JSON the client sees to the loguru lines in the
    server logs.
    """
    request_id = _request_id(request)
    logger.bind(request_id=request_id).exception(
        f"Unhandled exception in {request.method} {request.url.path}: {exc}"
    )
    spec = get_error_spec(ErrorCode.SERVER_INTERNAL_ERROR)
    return _envelope(
        request=request,
        code=ErrorCode.SERVER_INTERNAL_ERROR,
        status=spec.status,
        # Never leak the exception's message to ``user_message`` —
        # it might carry internal paths, SQL, or PII. Keep it in the
        # log line above and ship a generic envelope.
        message=type(exc).__name__,
        user_message=spec.user_message,
    )


def register_error_handlers(app: FastAPI) -> None:
    """Wire all exception handlers onto the app. Called once during
    startup from the app factory.

    Order matters at registration time: more specific handlers must
    register first so FastAPI's reverse-MRO lookup picks them. We
    handle that here so callers don't have to think about it.
    """
    app.add_exception_handler(ApiError, _handle_api_error)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
    app.add_exception_handler(HTTPException, _handle_http_exception)

    # Lazy-import the domain exceptions so this module can be imported
    # in test contexts where the managers themselves aren't wired.
    try:
        from pufferblow.api.friends.friends_manager import FriendsError

        app.add_exception_handler(FriendsError, _handle_friends_error)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(f"FriendsError handler not registered: {exc}")

    try:
        from pufferblow.api.stickers.stickers_manager import StickersError

        app.add_exception_handler(StickersError, _handle_stickers_error)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(f"StickersError handler not registered: {exc}")

    # Catch-all goes last so all of the above take precedence.
    app.add_exception_handler(Exception, _handle_unhandled_exception)
