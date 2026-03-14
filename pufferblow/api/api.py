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
from pufferblow.api.routes.register import register_routers
from pufferblow.api.routes.system_routes.server_runtime import (
    build_instance_health_payload,
)
from pufferblow.core.bootstrap import api_initializer
from pufferblow.server.middlewares import RateLimitingMiddleware, SecurityMiddleware


def _mount_static_routes() -> None:
    """Disable direct static file mounts for managed storage."""
    # All file access flows through storage route handlers so SSE decryption,
    # auth checks, and audit behavior remain centralized.
    return


def _load_cors_settings() -> tuple[list[str], bool, list[str], list[str]]:
    """Load CORS middleware settings from the shared config.toml."""
    config = ConfigHandler().build_bootstrap_config()
    return (
        list(config.CORS_ALLOWED_ORIGINS),
        config.CORS_ALLOW_CREDENTIALS,
        list(config.CORS_ALLOWED_METHODS),
        list(config.CORS_ALLOWED_HEADERS),
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan hook."""
    logger.info("API_STARTUP_BEGIN")

    if not api_initializer.is_loaded:
        api_initializer.load_objects()
        logger.info("API_INITIALIZER_LOADED")
    else:
        logger.info("API_INITIALIZER_ALREADY_LOADED")

    _mount_static_routes()

    async with lifespan_background_tasks():
        logger.info("API_STARTUP_COMPLETE")
        yield

    if api_initializer.database_handler is not None:
        try:
            api_initializer.database_handler.database_engine.dispose()
        except Exception:
            logger.warning("API_DATABASE_DISPOSE_FAILED")

    logger.info("API_SHUTDOWN_COMPLETE")


api = FastAPI(lifespan=lifespan)

cors_origins, cors_allow_credentials, cors_allow_methods, cors_allow_headers = (
    _load_cors_settings()
)
if cors_origins:
    api.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=cors_allow_credentials,
        allow_methods=cors_allow_methods,
        allow_headers=cors_allow_headers,
    )
else:
    logger.warning(
        "CORS middleware disabled because [security].cors_origins is not set in ~/.pufferblow/config.toml"
    )

api.add_middleware(SecurityMiddleware)
api.add_middleware(RateLimitingMiddleware)

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
    """Emit structured request logs with latency and status details."""
    request_id = str(uuid.uuid4())
    started_at = perf_counter()

    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if not client_ip and request.client:
        client_ip = request.client.host

    request_logger = logger.bind(
        request_id=request_id,
        method=request.method,
        path=request.url.path,
        client_ip=client_ip or "<unknown>",
    )
    request_logger.info("REQUEST_START")

    try:
        response = await call_next(request)
    except Exception:
        elapsed_ms = int((perf_counter() - started_at) * 1000)
        request_logger.exception(
            "REQUEST_FAILED duration_ms={duration_ms}",
            duration_ms=elapsed_ms,
        )
        raise

    elapsed_ms = int((perf_counter() - started_at) * 1000)
    status_code = response.status_code
    response.headers["X-Request-ID"] = request_id

    if status_code >= 500:
        request_logger.error(
            "REQUEST_END status_code={status_code} duration_ms={duration_ms}",
            status_code=status_code,
            duration_ms=elapsed_ms,
        )
    elif status_code >= 400:
        request_logger.warning(
            "REQUEST_END status_code={status_code} duration_ms={duration_ms}",
            status_code=status_code,
            duration_ms=elapsed_ms,
        )
    else:
        request_logger.info(
            "REQUEST_END status_code={status_code} duration_ms={duration_ms}",
            status_code=status_code,
            duration_ms=elapsed_ms,
        )

    return response
