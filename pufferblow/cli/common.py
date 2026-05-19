"""Shared helpers for CLI commands."""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

import typer
from loguru import logger

LOG_LEVEL_MAP = {
    0: "INFO",
    1: "DEBUG",
    2: "ERROR",
    3: "CRITICAL",
}

# Env vars used to forward CLI logging preferences across a process
# boundary. They exist for the uvicorn `--dev` reload path: uvicorn
# spawns a fresh worker subprocess on every file change and that
# worker imports the server app cold, so the logger configuration the
# CLI parent applied is lost. The worker reads these on import and
# re-applies the same configuration so every reload renders identical
# log lines.
ENV_LOG_LEVEL = "PUFFERBLOW_LOG_LEVEL"
ENV_DEBUG = "PUFFERBLOW_DEBUG"

if TYPE_CHECKING:
    from pufferblow.api.config.config_handler import ConfigHandler
    from pufferblow.api.models.config_model import Config


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


def cli_log_format(record: dict) -> str:
    """Compact log format for CLI commands.

    Uses the same `HH:mm:ss + level` prefix as the server's console
    sink (see `console_log_format`) so a single Pufferblow session
    looks coherent whether you're tailing the server or running a
    setup wizard — same timestamp shape, same level column width,
    same color semantics for ERROR / SUCCESS / WARNING.

    Drops the `name:line` source attribution the server format
    carries. Wizard output isn't debugging server code; the module
    path would be noise.
    """
    return (
        "<dim>{time:HH:mm:ss}</dim>  "
        "<level>{level: <8}</level>  "
        "{message}\n{exception}"
    )


def configure_cli_logging(*, level: str = "INFO") -> None:
    """Configure loguru for interactive CLI commands.

    Every emission from a `pufferblow` subcommand — validation
    failure, progress note, success summary — goes through loguru
    using `cli_log_format`. That makes the CLI output share its
    visual language with the server's console sink: same timestamp,
    same level column, same color cues. Operators don't have to
    context-switch between "looks like a Rich wizard" and "looks
    like a server log."

    Validation feedback ("Owner password required") goes through
    `logger.error`; success summaries through `logger.success`;
    progress / informational through `logger.info`. INFO is the
    default level because the wizard *is* the output — silencing
    info-level messages would hide the migration / setup progress
    the user is here to see.
    """
    logger.remove()
    logger.configure(patcher=enrich_log_record)
    # stdout, matching `console_log_format`'s sink in
    # `configure_server_logging`. Routing CLI emissions through stdout
    # means a `pufferblow setup | tee log` captures the wizard
    # transcript the same way it captures server logs — same stream,
    # same shape.
    logger.add(
        sys.stdout,
        level=level,
        format=cli_log_format,
        colorize=True,
        backtrace=False,
        diagnose=False,
    )


def configure_server_logging(
    *, config: Config, log_level: int, debug: bool
) -> str:
    """Configure stdlib/loguru integration and return resolved log level name.

    Used by the `serve` command and by `pufferblow.server.app` on
    import so that uvicorn-reload worker subprocesses (which start
    cold and lose the CLI parent's logger config) render the same
    structured lines as the parent.
    """
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


# Backwards-compat shim: the previous name is exported so anything
# importing it (third-party scripts, tests, in-flight branches) keeps
# working. New code should use `configure_server_logging`.
configure_structured_logging = configure_server_logging


def maybe_configure_server_logging_from_env() -> None:
    """Re-apply server logging in a child process spawned by uvicorn --reload.

    The CLI parent sets `PUFFERBLOW_LOG_LEVEL` / `PUFFERBLOW_DEBUG`
    before handing off to `uvicorn.run(..., reload=True)`. uvicorn
    spawns a watcher and a fresh worker subprocess on every file
    change; the worker imports `pufferblow.server.app` cold, which
    means loguru is back to its default sink and format. This helper
    is invoked from `pufferblow.server.app` on import — when those
    env vars are present, it rebuilds the same configuration the
    parent used so reload-driven restarts don't silently change the
    log format.

    A no-op when the env vars are missing (e.g. running under
    Gunicorn in production, where each worker shares the parent's
    process image and inherits the already-configured sinks).
    """
    level_raw = os.environ.get(ENV_LOG_LEVEL)
    if level_raw is None:
        return
    try:
        log_level = int(level_raw)
    except ValueError:
        return

    debug = os.environ.get(ENV_DEBUG, "0") == "1"
    try:
        config = load_config_or_exit()
    except Exception:
        # Worker came up without a usable bootstrap config or some
        # other transient failure — let the main server bootstrap
        # raise its own clearer error a few lines later rather than
        # crashing here on a best-effort log shim.
        return
    try:
        configure_server_logging(config=config, log_level=log_level, debug=debug)
    except Exception:
        return


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
