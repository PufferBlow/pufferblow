"""Wire envelopes for the Pufferblow command/event protocol (version 1).

Four message classes travel over the existing ``/ws`` connection:

* ``command``  client -> server, asks for an operation.
* ``ack``      server -> client, the command finished (committed) successfully.
* ``error``    server -> client, the command failed; carries a stable code.
* ``event``    server -> client, something already committed happened.

``hello`` is sent once, right after the connection is accepted, so a client
learns the supported versions and the server ``epoch`` it must use to detect
restarts. This module is transport independent: it builds and validates plain
dictionaries and never imports WebSocket or HTTP objects.
"""

from __future__ import annotations

import secrets
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

PROTOCOL_VERSION = 1
SUPPORTED_VERSIONS: tuple[int, ...] = (1,)

MAX_COMMAND_ID_LENGTH = 128
MAX_FRAME_BYTES = 64 * 1024


class ProtocolErrorCode:
    """Stable error codes. Part of the wire contract: never rename."""

    MALFORMED = "MALFORMED"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    UNKNOWN_COMMAND = "UNKNOWN_COMMAND"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    RATE_LIMITED = "RATE_LIMITED"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    INTERNAL = "INTERNAL"

    ALL = (
        MALFORMED,
        UNSUPPORTED_VERSION,
        UNKNOWN_COMMAND,
        UNAUTHENTICATED,
        PERMISSION_DENIED,
        NOT_FOUND,
        CONFLICT,
        RATE_LIMITED,
        PAYLOAD_TOO_LARGE,
        VALIDATION_FAILED,
        INTERNAL,
    )

    #: Codes a client may retry unchanged (with the same idempotency key).
    RETRYABLE = (RATE_LIMITED, CONFLICT, INTERNAL)


class CommandEnvelope(BaseModel):
    """A client request. ``id`` is chosen by the client and echoed in the reply."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["command"]
    version: int
    id: str = Field(min_length=1, max_length=MAX_COMMAND_ID_LENGTH)
    name: str = Field(min_length=1, max_length=64)
    data: dict[str, Any] = Field(default_factory=dict)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(12)}"


def new_event_id() -> str:
    """Server-generated, unique per event. Distinct from command and message ids."""
    return _new_id("evt")


def build_hello(*, session_id: str, epoch: str) -> dict[str, Any]:
    return {
        "type": "hello",
        "version": PROTOCOL_VERSION,
        "supported": list(SUPPORTED_VERSIONS),
        "session_id": session_id,
        "epoch": epoch,
    }


def build_ack(command_id: str, result: dict[str, Any] | None = None) -> dict[str, Any]:
    """``completed`` means the mutation has been committed, not merely accepted."""
    return {
        "type": "ack",
        "version": PROTOCOL_VERSION,
        "id": command_id,
        "data": {"status": "completed", "result": result or {}},
    }


def build_error(
    command_id: str | None,
    code: str,
    message: str,
    *,
    retry_after: float | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """An error reply. ``message`` must already be safe to show to a user."""
    error: dict[str, Any] = {
        "code": code,
        "message": message,
        "retryable": code in ProtocolErrorCode.RETRYABLE,
    }
    if retry_after is not None:
        error["retry_after"] = round(retry_after, 3)
    if details:
        error["details"] = details
    return {"type": "error", "version": PROTOCOL_VERSION, "id": command_id, "error": error}


def build_event(
    name: str,
    data: dict[str, Any],
    *,
    channel_id: str | None = None,
    seq: int | None = None,
    epoch: str | None = None,
    event_id: str | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "type": "event",
        "version": PROTOCOL_VERSION,
        "id": event_id or new_event_id(),
        "name": name,
        "data": data,
    }
    if channel_id is not None:
        event["channel_id"] = channel_id
    if seq is not None:
        event["seq"] = seq
    if epoch is not None:
        event["epoch"] = epoch
    return event


# ── server-to-client models ─────────────────────────────────────
# The builders above produce plain dicts for speed. These models describe the same
# shapes so tests, the JSON Schema export and future SDKs share one definition.


class HelloEnvelope(BaseModel):
    type: Literal["hello"]
    version: int
    supported: list[int]
    session_id: str
    epoch: str


class AckData(BaseModel):
    status: Literal["completed"]
    result: dict[str, Any] = Field(default_factory=dict)
    duplicate: bool | None = None


class AckEnvelope(BaseModel):
    type: Literal["ack"]
    version: int
    id: str
    data: AckData


class ErrorBody(BaseModel):
    code: str
    message: str
    retryable: bool = False
    retry_after: float | None = None
    details: dict[str, Any] | None = None


class ErrorEnvelope(BaseModel):
    type: Literal["error"]
    version: int
    #: The command id the error answers, or null when the frame was too broken to have one.
    id: str | None
    error: ErrorBody


class EventEnvelope(BaseModel):
    type: Literal["event"]
    version: int
    id: str
    name: str
    channel_id: str | None = None
    seq: int | None = None
    epoch: str | None = None
    data: dict[str, Any]


def protocol_json_schema() -> dict[str, Any]:
    """One JSON Schema document describing every frame and every command payload."""
    from pufferblow.api.protocol.commands import COMMAND_SCHEMAS

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Pufferblow command/event protocol",
        "x-protocol-version": PROTOCOL_VERSION,
        "frames": {
            "command": CommandEnvelope.model_json_schema(),
            "hello": HelloEnvelope.model_json_schema(),
            "ack": AckEnvelope.model_json_schema(),
            "error": ErrorEnvelope.model_json_schema(),
            "event": EventEnvelope.model_json_schema(),
        },
        "commands": {name: model.model_json_schema() for name, model in COMMAND_SCHEMAS.items()},
        "error_codes": list(ProtocolErrorCode.ALL),
    }
