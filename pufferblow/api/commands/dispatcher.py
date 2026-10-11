"""The central command dispatcher.

``dispatch`` takes one raw client frame and returns the reply plus the domain
events to publish. It knows nothing about WebSockets or HTTP: the caller owns the
transport, sends the reply, then publishes the events. That ordering means a
client sees its acknowledgment for work that is already committed, and no event
is ever emitted for a mutation that failed.
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from loguru import logger
from pydantic import BaseModel, ValidationError

from pufferblow.api.commands.metrics import metrics
from pufferblow.api.commands.ratelimit import RateLimiter
from pufferblow.api.principals.principal import Principal
from pufferblow.api.protocol.envelopes import (
    MAX_FRAME_BYTES,
    SUPPORTED_VERSIONS,
    CommandEnvelope,
    ProtocolErrorCode,
    build_ack,
    build_error,
)
from pufferblow.api.protocol.errors import ProtocolError, to_wire_error
from pufferblow.api.protocol.events import DomainEvent


@dataclass
class ConnectionContext:
    """Everything a command needs to know about the caller, with no transport objects."""

    principal: Principal
    session_id: str
    connection_key: str
    #: Channel ids this connection receives events for. The connection manager shares this very set.
    subscriptions: set[str] = field(default_factory=set)
    #: Re-validates the connection's credential and returns the current principal, or raises.
    #: Closes over the token so the secret is never stored on the context or logged.
    revalidate: Callable[[], Principal] | None = None


@dataclass
class HandlerOutput:
    result: dict[str, Any]
    events: list[DomainEvent] = field(default_factory=list)


Handler = Callable[[ConnectionContext, Any], Awaitable[HandlerOutput]]


@dataclass(frozen=True)
class CommandSpec:
    name: str
    schema: type[BaseModel]
    handler: Handler
    #: Returns the idempotency key for a payload, or None when the command is not deduplicated.
    idempotency_key: Callable[[Any], str | None] | None = None


@dataclass
class DispatchResult:
    reply: dict[str, Any]
    events: list[DomainEvent] = field(default_factory=list)


class CommandDispatcher:
    def __init__(
        self,
        registry: dict[str, CommandSpec],
        *,
        idempotency_store=None,
        principal_limiter: RateLimiter | None = None,
        connection_limiter: RateLimiter | None = None,
    ) -> None:
        self._registry = registry
        self._store = idempotency_store
        self._principal_limiter = principal_limiter or RateLimiter(capacity=30, refill_per_second=10)
        self._connection_limiter = connection_limiter or RateLimiter(capacity=20, refill_per_second=5)

    # ── public API ────────────────────────────────────────────

    async def dispatch(self, ctx: ConnectionContext, raw: str | bytes | dict) -> DispatchResult:
        started = time.perf_counter()
        command_id: str | None = None
        name = "unknown"
        try:
            frame = self._parse(raw)
            command_id = frame["id"] if isinstance(frame.get("id"), str) else None
            envelope = self._validate_envelope(frame)
            name = envelope.name

            spec = self._registry.get(name)
            if spec is None:
                raise ProtocolError(ProtocolErrorCode.UNKNOWN_COMMAND, f"Unknown command '{name[:64]}'.")

            data = self._validate_data(spec, envelope.data)
            self._enforce_rate_limit(ctx)
            if ctx.revalidate is not None:
                # Expired, revoked or banned credentials stop working mid-connection, and role
                # changes take effect on the next command.
                ctx.principal = ctx.revalidate()

            output, duplicate = await self._run(spec, ctx, data, envelope.name)
            reply = build_ack(envelope.id, output.result)
            if duplicate:
                reply["data"]["duplicate"] = True
            self._record(name, "duplicate" if duplicate else "ok", started, ctx)
            return DispatchResult(reply=reply, events=[] if duplicate else output.events)

        except Exception as exc:  # noqa: BLE001 - everything becomes a protocol error
            code, message, retry_after = to_wire_error(exc)
            if code == ProtocolErrorCode.INTERNAL:
                logger.opt(exception=exc).error(f"Command failed unexpectedly | command={name}")
            self._record(name, code.lower(), started, ctx, code=code)
            return DispatchResult(reply=build_error(command_id, code, message, retry_after=retry_after))

    # ── steps ─────────────────────────────────────────────────

    def _parse(self, raw: str | bytes | dict) -> dict[str, Any]:
        if isinstance(raw, dict):
            return raw
        size = len(raw)
        if size > MAX_FRAME_BYTES:
            raise ProtocolError(ProtocolErrorCode.PAYLOAD_TOO_LARGE, "Frame is too large.")
        try:
            frame = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise ProtocolError(ProtocolErrorCode.MALFORMED, "Frame is not valid JSON.") from None
        if not isinstance(frame, dict):
            raise ProtocolError(ProtocolErrorCode.MALFORMED, "Frame must be a JSON object.")
        return frame

    def _validate_envelope(self, frame: dict[str, Any]) -> CommandEnvelope:
        if frame.get("type") != "command":
            raise ProtocolError(ProtocolErrorCode.MALFORMED, "Only frames of type 'command' are accepted.")
        version = frame.get("version")
        if version not in SUPPORTED_VERSIONS or isinstance(version, bool):
            raise ProtocolError(
                ProtocolErrorCode.UNSUPPORTED_VERSION,
                f"Protocol version {version!r} is not supported. Supported: {list(SUPPORTED_VERSIONS)}.",
            )
        try:
            return CommandEnvelope.model_validate(frame)
        except ValidationError as exc:
            raise ProtocolError(ProtocolErrorCode.MALFORMED, f"Invalid command envelope: {self._fields(exc)}.") from None

    def _validate_data(self, spec: CommandSpec, data: dict[str, Any]) -> BaseModel:
        try:
            return spec.schema.model_validate(data)
        except ValidationError as exc:
            raise ProtocolError(
                ProtocolErrorCode.VALIDATION_FAILED, f"Invalid data for {spec.name}: {self._fields(exc)}."
            ) from None

    @staticmethod
    def _fields(exc: ValidationError) -> str:
        # Field names and error kinds only: never echo the values a client sent.
        parts = sorted({f"{'.'.join(str(p) for p in e['loc']) or 'frame'} ({e['type']})" for e in exc.errors()})
        return ", ".join(parts[:6])

    def _enforce_rate_limit(self, ctx: ConnectionContext) -> None:
        wait = self._connection_limiter.check(ctx.connection_key)
        if wait is None:
            wait = self._principal_limiter.check(ctx.principal.id)
        if wait is not None:
            metrics.incr("rate_limited")
            raise ProtocolError(ProtocolErrorCode.RATE_LIMITED, "You are sending commands too quickly.", retry_after=wait)

    async def _run(self, spec: CommandSpec, ctx: ConnectionContext, data: BaseModel, name: str) -> tuple[HandlerOutput, bool]:
        key = spec.idempotency_key(data) if spec.idempotency_key and self._store else None
        if key is None:
            return await spec.handler(ctx, data), False

        principal_id = ctx.principal.id
        state, stored = self._store.reserve_idempotency_key(principal_id, name, key)
        if state == "completed":
            metrics.incr("duplicate_commands")
            return HandlerOutput(result=stored or {}), True
        if state == "in_progress":
            metrics.incr("duplicate_commands")
            raise ProtocolError(
                ProtocolErrorCode.CONFLICT, "This command is still being processed. Retry shortly.", retry_after=1.0
            )

        try:
            output = await spec.handler(ctx, data)
        except BaseException:
            # Nothing was committed, or we cannot tell: free the key so a retry runs for real.
            self._store.release_idempotency_key(principal_id, name, key)
            raise
        self._store.complete_idempotency_key(principal_id, name, key, output.result)
        return output, False

    def _record(self, name: str, outcome: str, started: float, ctx: ConnectionContext, *, code: str | None = None) -> None:
        elapsed = time.perf_counter() - started
        metrics.incr(f"commands.{name}.{outcome}")
        metrics.observe_latency(name, elapsed)
        if code in (ProtocolErrorCode.PERMISSION_DENIED, ProtocolErrorCode.UNAUTHENTICATED):
            metrics.incr("authorization_failures")
        elif code in (ProtocolErrorCode.VALIDATION_FAILED, ProtocolErrorCode.MALFORMED, ProtocolErrorCode.UNKNOWN_COMMAND):
            metrics.incr("validation_failures")
        # Deliberately no payload, no tokens, no message text.
        logger.info(
            "COMMAND command={command} outcome={outcome} latency_ms={latency} principal_kind={kind} session={session}",
            command=name,
            outcome=outcome,
            latency=int(elapsed * 1000),
            kind=ctx.principal.kind,
            session=ctx.session_id,
        )
