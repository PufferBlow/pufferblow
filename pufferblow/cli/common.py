"""Shared helpers for CLI commands."""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass

import typer
from loguru import logger
from rich.console import Console

from pufferblow.api.config.config_handler import ConfigHandler
from pufferblow.api.database.database import Database
from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.logger.levels import LOG_LEVEL_MAP
from pufferblow.api.logger.logger import (
    WORKERS,
    InterceptHandler,
    StandaloneApplication,
    StubbedGunicornLogger,
)
from pufferblow.api.models.config_model import Config
from pufferblow.core.bootstrap import api_initializer

console = Console()

INFORMATIVE_LOG_FORMAT = (
    "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level:<8} | "
    "request_id={extra[request_id]} | method={extra[method]} | path={extra[path]} | "
    "status={extra[status_code]} | duration_ms={extra[duration_ms]} | client_ip={extra[client_ip]} | "
    "{name}:{function}:{line} | {message}"
)

COLOR_LOG_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level:<8}</level> | "
    "<cyan>request_id={extra[request_id]}</cyan> | "
    "<blue>method={extra[method]}</blue> | "
    "<blue>path={extra[path]}</blue> | "
    "<magenta>status={extra[status_code]}</magenta> | "
    "<yellow>duration_ms={extra[duration_ms]}</yellow> | "
    "<cyan>client_ip={extra[client_ip]}</cyan> | "
    "<dim>{name}:{function}:{line}</dim> | "
    "<level>{message}</level>"
)


@dataclass(slots=True)
class DatabaseCredentials:
    """Represents user-provided database connection details."""

    database_name: str
    username: str
    password: str
    host: str
    port: int


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
    return Database._create_database_uri(
        username=credentials.username,
        password=credentials.password,
        host=credentials.host,
        port=int(credentials.port),
        database_name=credentials.database_name,
    )


def ensure_database_exists(database_uri: str) -> None:
    """Exit with a useful message if the target database is unreachable."""
    if not Database.check_database_existense(database_uri):
        logger.error(
            "The specified database does not exist or is unreachable. "
            "Verify database name, host, port, and credentials."
        )
        raise typer.Exit(code=1)


def load_config_or_exit(config_handler: ConfigHandler | None = None) -> Config:
    """Load config from disk or exit with guidance."""
    handler = config_handler or ConfigHandler()
    if not handler.check_config():
        logger.error(
            "Configuration file not found. Run 'pufferblow setup' before serving."
        )
        raise typer.Exit(code=1)
    return Config(config=handler.load_config())


def load_runtime(*, database_uri: str | None = None, setup_tables: bool = False) -> None:
    """Initialize shared managers and optionally ensure DB tables exist."""
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

    seen_roots: set[str] = set()
    for name in [
        *logging.root.manager.loggerDict.keys(),
        "gunicorn",
        "gunicorn.access",
        "gunicorn.error",
        "uvicorn",
        "uvicorn.access",
        "uvicorn.error",
    ]:
        root_name = name.split(".")[0]
        if root_name in seen_roots:
            continue
        seen_roots.add(root_name)
        logging.getLogger(name).handlers = [intercept_handler]

    logger.remove()
    logger.add(
        sys.stdout,
        level=log_level_name,
        format=COLOR_LOG_FORMAT,
        colorize=True,
        backtrace=debug,
        diagnose=debug,
    )
    logger.add(
        config.LOGS_PATH,
        rotation="10 MB",
        level=log_level_name,
        format=INFORMATIVE_LOG_FORMAT,
        colorize=False,
    )
    return log_level_name


def run_gunicorn_server(*, app, config: Config, log_level_name: str) -> None:
    """Run the production API process via Gunicorn + Uvicorn workers."""
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

