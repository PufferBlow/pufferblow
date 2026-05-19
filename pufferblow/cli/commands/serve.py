"""Serve command for starting API server processes."""

from __future__ import annotations

import os

from loguru import logger


def serve_command(
    log_level: int = 0,
    debug: bool = False,
    dev: bool = False,
) -> None:
    """Start the API server.

    Argument metadata (flag names, help strings) lives in
    `pufferblow.cli.cli._build_parser`. The implementation here only
    cares about the resolved values.
    """
    from pufferblow.api.config.config_handler import ConfigHandler
    from pufferblow.cli.common import (
        ENV_DEBUG,
        ENV_LOG_LEVEL,
        configure_server_logging,
        ensure_database_exists,
        load_config_or_exit,
        load_runtime,
        run_gunicorn_server,
    )
    from pufferblow.core.bootstrap import api_initializer

    if debug:
        log_level = 1

    config_handler = ConfigHandler()
    config = load_config_or_exit()
    database_uri = config_handler.resolve_database_uri()
    if not database_uri:
        logger.error("No bootstrap database URI found. Run `pufferblow setup` first.")
        raise SystemExit(1)

    # Configure logging before load_runtime so startup/DB-setup logs use the
    # same format as everything that follows, not Loguru's bare default.
    log_level_name = configure_server_logging(
        config=config,
        log_level=log_level,
        debug=debug,
    )

    ensure_database_exists(database_uri)
    load_runtime(database_uri=database_uri, setup_tables=True)
    config = api_initializer.config

    if dev:
        logger.info("Starting development server with hot reload.")
        try:
            import uvicorn

            # Forward the resolved log preferences across the
            # process boundary. uvicorn's `reload=True` spawns a
            # fresh worker subprocess on every file change; that
            # worker imports `pufferblow.server.app` cold and would
            # otherwise lose this logger configuration. The worker
            # re-applies it on import via
            # `maybe_configure_server_logging_from_env`.
            os.environ[ENV_LOG_LEVEL] = str(log_level)
            os.environ[ENV_DEBUG] = "1" if debug else "0"

            uvicorn.run(
                "pufferblow.server.app:api",
                host=config.API_HOST,
                port=int(config.API_PORT),
                reload=True,
                log_level=log_level_name.lower(),
                log_config=None,
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
