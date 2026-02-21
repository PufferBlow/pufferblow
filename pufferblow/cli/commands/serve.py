"""Serve command for starting API server processes."""

from __future__ import annotations

import typer
from loguru import logger

from pufferblow.cli.common import (
    build_database_uri_from_config,
    configure_structured_logging,
    ensure_database_exists,
    load_config_or_exit,
    load_runtime,
    run_gunicorn_server,
)


def serve_command(
    log_level: int = typer.Option(
        0,
        "--log-level",
        help="Log level [0=INFO, 1=DEBUG, 2=ERROR, 3=CRITICAL].",
    ),
    debug: bool = typer.Option(
        False, "--debug", help="Enable debug traces and diagnostics."
    ),
    dev: bool = typer.Option(
        False, "--dev", help="Run with uvicorn auto-reload for development."
    ),
) -> None:
    """Start the API server."""
    if debug:
        log_level = 1

    config = load_config_or_exit()
    database_uri = build_database_uri_from_config(config)
    ensure_database_exists(database_uri)
    load_runtime(database_uri=database_uri, setup_tables=True)

    log_level_name = configure_structured_logging(
        config=config,
        log_level=log_level,
        debug=debug,
    )

    if dev:
        logger.info("Starting development server with hot reload.")
        try:
            import uvicorn

            uvicorn.run(
                "pufferblow.server.app:api",
                host=config.API_HOST,
                port=int(config.API_PORT),
                reload=True,
                log_level=log_level_name.lower(),
                access_log=False,
                server_header=False,
                date_header=False,
            )
            return
        except ImportError:
            logger.warning(
                "uvicorn is not available. Falling back to production process mode."
            )

    from pufferblow.server.app import api

    run_gunicorn_server(app=api, config=config, log_level_name=log_level_name)

