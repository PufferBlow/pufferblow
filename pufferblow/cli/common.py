"""Shared helpers for CLI commands."""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

import typer
from loguru import logger
from rich.console import Console

LOG_LEVEL_MAP = {
    0: "INFO",
    1: "DEBUG",
    2: "ERROR",
    3: "CRITICAL",
}

if TYPE_CHECKING:
    from pufferblow.api.config.config_handler import ConfigHandler
    from pufferblow.api.models.config_model import Config

console = Console()

def _has_request_context(extra: dict) -> bool:
    """True when the record was emitted inside an HTTP request scope."""
    return extra.get("method", "-") != "-" and extra.get("path", "-") != "-"


def console_log_format(record: dict) -> str:
    """
    Tone-down terminal format. Color is restricted to the level tag and
    a dim timestamp/location; the rainbow of per-field colors is gone.
    HTTP request fields (method/path/status/duration) are only rendered
    when the record was emitted inside a request — background tasks,
    startup and scheduler logs no longer print 'method=- path=- status=-'.
    """
    template = (
        "<dim>{time:HH:mm:ss}</dim>  "
        "<level>{level: <8}</level>"
    )
    if _has_request_context(record["extra"]):
        template += (
            "  <cyan>{extra[method]: <6}</cyan>"
            "<blue>{extra[path]}</blue>"
            "  <magenta>{extra[status_code]}</magenta>"
            "  <yellow>{extra[duration_ms]}ms</yellow>"
        )
    template += "  <dim>{name}:{line}</dim>  {message}\n{exception}"
    return template


def file_log_format(record: dict) -> str:
    """
    Plain-text file format. Same conditional treatment of HTTP request
    fields as the console variant so the file is not padded with '-'
    placeholders for non-request logs. Tracebacks are appended via
    {exception} which the previous static format string was missing.
    """
    template = "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level:<8}"
    if _has_request_context(record["extra"]):
        template += (
            " | {extra[method]} {extra[path]}"
            " status={extra[status_code]}"
            " duration={extra[duration_ms]}ms"
            " client={extra[client_ip]}"
            " req={extra[request_id]}"
        )
    template += " | {name}:{function}:{line} | {message}\n{exception}"
    return template


@dataclass(slots=True)
class DatabaseCredentials:
    """Represents user-provided database connection details."""

    database_name: str
    username: str
    password: str
    host: str
    port: int


class InterceptHandler(logging.Handler):
    """Forward stdlib logging records to Loguru without importing Gunicorn helpers."""

    def emit(self, record: logging.LogRecord) -> None:
        """Emit a stdlib log record through Loguru."""
        try:
            level: str | int = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame = sys._getframe(6)
        depth = 6
        while frame and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


def enrich_log_record(record: dict) -> None:
    """Ensure expected structured log fields are always present."""
    extra = record["extra"]
    extra.setdefault("request_id", "-")
    extra.setdefault("method", "-")
    extra.setdefault("path", "-")
    extra.setdefault("status_code", "-")
    extra.setdefault("duration_ms", "-")
    extra.setdefault("client_ip", "-")


def build_database_uri_from_config(config: Config) -> str:
    """Build a database URI from a config object."""
    from pufferblow.api.database.database import Database

    return Database._create_database_uri(
        username=config.USERNAME,
        password=config.DATABASE_PASSWORD,
        host=config.DATABASE_HOST,
        port=int(config.DATABASE_PORT),
        database_name=config.DATABASE_NAME,
        ssl_mode=config.DATABASE_SSL_MODE,
        ssl_cert=config.DATABASE_SSL_CERT,
        ssl_key=config.DATABASE_SSL_KEY,
        ssl_root_cert=config.DATABASE_SSL_ROOT_CERT,
    )


def build_database_uri_from_credentials(credentials: DatabaseCredentials) -> str:
    """Build a database URI from explicit credential inputs."""
    from pufferblow.api.database.database import Database

    return Database._create_database_uri(
        username=credentials.username,
        password=credentials.password,
        host=credentials.host,
        port=int(credentials.port),
        database_name=credentials.database_name,
    )


def ensure_database_exists(database_uri: str) -> None:
    """Exit with a useful message if the target database is unreachable."""
    from pufferblow.api.database.database import Database

    if not Database.check_database_existense(database_uri):
        logger.error(
            "The specified database does not exist or is unreachable. "
            "Verify database name, host, port, and credentials."
        )
        raise typer.Exit(code=1)


def load_config_or_exit(config_handler: ConfigHandler | None = None) -> Config:
    """Load bootstrap config from environment or exit with guidance."""
    from pufferblow.api.config.config_handler import ConfigHandler

    handler = config_handler or ConfigHandler()
    if not handler.resolve_database_uri():
        logger.error(
            "No bootstrap database URI found. Run `pufferblow setup` first."
        )
        raise typer.Exit(code=1)
    return handler.build_bootstrap_config()


def load_runtime(*, database_uri: str | None = None, setup_tables: bool = False) -> None:
    """Initialize shared managers and optionally ensure DB tables exist."""
    from pufferblow.api.database.tables.declarative_base import Base
    from pufferblow.core.bootstrap import api_initializer

    api_initializer.load_objects(database_uri=database_uri)
    if setup_tables:
        api_initializer.database_handler.setup_tables(Base)


def configure_structured_logging(
    *, config: Config, log_level: int, debug: bool
) -> str:
    """Configure stdlib/loguru integration and return resolved log level name."""
    if log_level not in LOG_LEVEL_MAP:
        logger.error("Invalid log level: {level}. Allowed: 0..3.", level=log_level)
        raise typer.Exit(code=1)

    log_level_name = LOG_LEVEL_MAP[log_level]
    logger.configure(patcher=enrich_log_record)

    intercept_handler = InterceptHandler()
    logging.basicConfig(handlers=[intercept_handler], level=log_level_name)
    logging.root.handlers = [intercept_handler]
    logging.root.setLevel(log_level_name)

    _always_intercept = [
        "uvicorn",
        "uvicorn.access",
        "uvicorn.error",
        "gunicorn",
        "gunicorn.access",
        "gunicorn.error",
    ]
    seen: set[str] = set()
    for name in [*logging.root.manager.loggerDict.keys(), *_always_intercept]:
        if name in seen:
            continue
        seen.add(name)
        log = logging.getLogger(name)
        log.handlers = [intercept_handler]
        log.propagate = False

    logger.remove()
    logger.add(
        sys.stdout,
        level=log_level_name,
        format=console_log_format,
        colorize=True,
        backtrace=debug,
        diagnose=debug,
    )
    logger.add(
        config.LOGS_PATH,
        rotation="10 MB",
        level=log_level_name,
        format=file_log_format,
        colorize=False,
    )
    return log_level_name


def run_gunicorn_server(*, app, config: Config, log_level_name: str) -> None:
    """Run the production API process via Gunicorn + Uvicorn workers."""
    from pufferblow.api.logger.logger import (
        WORKERS,
        StandaloneApplication,
        StubbedGunicornLogger,
    )

    StubbedGunicornLogger.log_level = log_level_name
    options = {
        "bind": f"{config.API_HOST}:{config.API_PORT}",
        "workers": WORKERS(config.WORKERS),
        "timeout": 86400,
        "keepalive": 86400,
        "accesslog": "-",
        "errorlog": "-",
        "worker_class": "uvicorn.workers.UvicornWorker",
        "logger_class": StubbedGunicornLogger,
    }
    StandaloneApplication(app, options).run()
