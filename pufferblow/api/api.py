"""FastAPI application bootstrap for PufferBlow server."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from time import perf_counter

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from pufferblow.api.background_tasks.background_tasks_manager import (
    lifespan_background_tasks,
)
from pufferblow.api.config.config_handler import ConfigHandler
from pufferblow.api.errors import register_error_handlers
from pufferblow.api.routes.register import register_routers
from pufferblow.api.routes.system_routes.server_runtime import (
    build_instance_health_payload,
)
from pufferblow.core.bootstrap import api_initializer
from pufferblow.server.middlewares import (
    PrivateNetworkAccessMiddleware,
    RateLimitingMiddleware,
    SecurityMiddleware,
)


def _mount_static_routes() -> None:
    """Disable direct static file mounts for managed storage."""
    # All file access flows through storage route handlers so SSE decryption,
    # auth checks, and audit behavior remain centralized.
    return


def _load_cors_settings() -> tuple[list[str], str | None, bool, list[str], list[str]]:
    """Load CORS middleware settings from the shared config.toml."""
    config = ConfigHandler().build_bootstrap_config()
    return (
        list(config.CORS_ALLOWED_ORIGINS),
        config.CORS_ALLOWED_ORIGIN_REGEX,
        config.CORS_ALLOW_CREDENTIALS,
        list(config.CORS_ALLOWED_METHODS),
        list(config.CORS_ALLOWED_HEADERS),
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan hook.

    Emits a small number of human-readable milestones rather than the
    old shouty `API_STARTUP_BEGIN` / `API_INITIALIZER_LOADED` event
    names. Operators reading the log should be able to tell at a
    glance "where is the boot stuck?" — so the lines read like a
    progress report, not a key-value enum.
    """
    logger.info("Server starting…")

    if not api_initializer.is_loaded:
        api_initializer.load_objects()
        logger.info("API initializer loaded")
    else:
        logger.info("API initializer already loaded — reusing")

    _mount_static_routes()

    async with lifespan_background_tasks():
        logger.success("Server ready — accepting requests")
        yield

    logger.info("Server shutting down…")
    if api_initializer.database_handler is not None:
        try:
            api_initializer.database_handler.database_engine.dispose()
        except Exception:
            logger.warning("Database engine dispose failed — continuing shutdown")

    logger.info("Server stopped")


api = FastAPI(lifespan=lifespan)

(
    cors_origins,
    cors_origin_regex,
    cors_allow_credentials,
    cors_allow_methods,
    cors_allow_headers,
) = _load_cors_settings()
api.add_middleware(SecurityMiddleware)
api.add_middleware(RateLimitingMiddleware)
# Middleware order, from innermost to outermost (the LAST add_middleware
# call is OUTERMOST in Starlette's stack):
#
#   SecurityMiddleware           (innermost; param validation)
#   RateLimitingMiddleware
#   CORSMiddleware               (attaches Access-Control-Allow-Origin
#                                 to every response, including the
#                                 4xx/5xx that the inner middleware
#                                 returns)
#   PrivateNetworkAccessMiddleware (outermost; decorates the CORS
#                                 preflight with the extra PNA header
#                                 when the browser requested it)
#
# PNA being outermost is deliberate. CORSMiddleware short-circuits on
# preflight requests — it builds the response itself without calling
# downstream. We need to see and modify that already-built response,
# which means sitting one layer further out. PNA does NOT replace CORS
# auth: a preflight that CORS declines still has no
# Access-Control-Allow-Origin, and the browser will reject it
# regardless of the PNA header.
if cors_origins or cors_origin_regex:
    api.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_origin_regex=cors_origin_regex,
        allow_credentials=cors_allow_credentials,
        allow_methods=cors_allow_methods,
        allow_headers=cors_allow_headers,
    )
else:
    logger.warning(
        "CORS middleware disabled because [security].cors_origins or [security].cors_origin_regex is not set in ~/.pufferblow/config.toml"
    )
api.add_middleware(PrivateNetworkAccessMiddleware)

# Register the global error handlers BEFORE the routers so any
# exception raised during route registration (e.g. an import-time
# bug in a route module) goes through the envelope path too. Idempotent
# either way — FastAPI replaces handlers on re-registration.
register_error_handlers(api)
register_routers(api)


@api.get("/healthz", status_code=200)
async def healthz():
    """Instance health endpoint including mirrored media-sfu health."""
    return build_instance_health_payload()


@api.get("/readyz", status_code=200)
async def readyz():
    """Alias for instance readiness/health endpoint."""
    return build_instance_health_payload()


@api.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    """Emit human-readable request logs with latency and status details.

    Two lines per request: one on entry (`» GET /path`) and one on
    exit (`« 200 GET /path in 5ms`). The level on the exit line
    tracks the status class — INFO for 2xx/3xx, WARNING for 4xx,
    ERROR for 5xx — so an operator can `--level WARNING` and
    immediately see every client / server fault without grepping for
    status codes. Loguru's level palette carries the colour (green
    for INFO, yellow for WARN, red for ERROR); the message stays as
    plain text so URL paths can't accidentally inject markup tags
    into the colour parser.

    Both lines bind the same `request_id` / `method` / `path` /
    `client_ip` to the loguru extras, so the file sink emits them
    structurally (one per `key=value` field) even though the console
    sink keeps them out of the prefix.
    """
    request_id = str(uuid.uuid4())
    started_at = perf_counter()

    # Stash on request.state so the global exception handlers can
    # include the same id in the error envelope they emit. Both the
    # response header (set further down) and the envelope field
    # carry the same value, so a user reporting a problem can paste
    # either one for support correlation.
    request.state.request_id = request_id

    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if not client_ip and request.client:
        client_ip = request.client.host

    method = request.method
    path = request.url.path

    request_logger = logger.bind(
        request_id=request_id,
        method=method,
        path=path,
        client_ip=client_ip or "<unknown>",
    )
    request_logger.info(f"» {method} {path}")

    try:
        response = await call_next(request)
    except Exception:
        elapsed_ms = int((perf_counter() - started_at) * 1000)
        request_logger.bind(
            status_code="ERR",
            duration_ms=elapsed_ms,
        ).exception(f"× {method} {path} crashed after {elapsed_ms}ms")
        raise

    elapsed_ms = int((perf_counter() - started_at) * 1000)
    status_code = response.status_code
    response.headers["X-Request-ID"] = request_id

    line = f"« {status_code} {method} {path} in {elapsed_ms}ms"
    exit_logger = request_logger.bind(
        status_code=status_code,
        duration_ms=elapsed_ms,
    )

    if status_code >= 500:
        exit_logger.error(line)
    elif status_code >= 400:
        exit_logger.warning(line)
    else:
        exit_logger.info(line)

    return response
