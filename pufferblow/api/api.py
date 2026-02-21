"""FastAPI application bootstrap for PufferBlow server."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from time import perf_counter

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from loguru import logger

from pufferblow.api.background_tasks.background_tasks_manager import (
    lifespan_background_tasks,
)
from pufferblow.api.routes.register import register_routers
from pufferblow.core.bootstrap import api_initializer
from pufferblow.server.middlewares import RateLimitingMiddleware, SecurityMiddleware


ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://172.19.224.1:5173",
    "http://localhost:7575",
    "http://127.0.0.1:7575",
    "https://pufferblow.space",
    "https://www.pufferblow.space",
    "http://pufferblow.space",
    "http://www.pufferblow.space",
]


def _route_name_exists(app: FastAPI, route_name: str) -> bool:
    """Check whether a mounted route name already exists."""
    for route in app.router.routes:
        if getattr(route, "name", None) == route_name:
            return True
    return False


def _mount_static_routes(app: FastAPI) -> None:
    """Mount CDN and storage static routes once config is available."""
    if not api_initializer.is_loaded:
        return

    if not _route_name_exists(app, "cdn"):
        app.mount(
            api_initializer.config.CDN_BASE_URL,
            StaticFiles(directory=api_initializer.config.CDN_STORAGE_PATH, check_dir=False),
            name="cdn",
        )

    if not _route_name_exists(app, "storage"):
        app.mount(
            api_initializer.config.STORAGE_BASE_URL,
            StaticFiles(directory=api_initializer.config.STORAGE_PATH, check_dir=False),
            name="storage",
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

    _mount_static_routes(app)

    async with lifespan_background_tasks():
        logger.info("API_STARTUP_COMPLETE")
        yield

    logger.info("API_SHUTDOWN_COMPLETE")


api = FastAPI(lifespan=lifespan)

api.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
api.add_middleware(SecurityMiddleware)
api.add_middleware(RateLimitingMiddleware)

register_routers(api)


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
