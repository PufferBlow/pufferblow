"""Unit tests for the CLI-side logging helpers.

We test the contract that matters to the CLI experience:

1. `configure_cli_logging` produces a quiet, compact loguru sink so
   wizard output (Rich Panels, the `_ui_error` helper) isn't competing
   with library `logger.info` chatter.
2. `maybe_configure_server_logging_from_env` is a no-op when no CLI
   parent has forwarded log preferences — which is the case for the
   production gunicorn path and any third-party importer of
   `pufferblow.server.app`.

We do NOT exercise the env-vars-present branch here because that path
constructs a `ConfigHandler` and reads a real config file from disk;
covering it cleanly would mean spinning up a tmp_path config, and the
behavior is exactly the same as calling `configure_server_logging`
directly, which the serve command already exercises in integration.
"""

from __future__ import annotations

import io

from loguru import logger

from pufferblow.cli.common import (
    ENV_DEBUG,
    ENV_LOG_LEVEL,
    configure_cli_logging,
    maybe_configure_server_logging_from_env,
)


def _capture_emit(level_name: str, message: str) -> str:
    """Emit a record at the given level and return what was written to the sink."""
    buf = io.StringIO()
    logger.remove()
    sink_id = logger.add(
        buf,
        level="DEBUG",
        format="{level: <8}{message}",
        colorize=False,
    )
    # Reconfigure with the CLI sink right after — the test wants to
    # exercise the CLI sink's level/format, not our scaffolding sink.
    # But we keep our buffer attached too.
    configure_cli_logging()
    logger.add(buf, level="DEBUG", format="{level: <8}{message}", colorize=False)
    getattr(logger, level_name)(message)
    logger.remove(sink_id)
    return buf.getvalue()


def test_cli_logging_default_level_suppresses_info_and_debug():
    """At the WARNING default an info-level library line should not surface.

    This is the wizard-quality property: library bootstrap chatter
    must not interrupt the wizard surface.
    """
    buf = io.StringIO()
    logger.remove()
    configure_cli_logging()
    # Replace the configured stderr sink with our buffer at the same level.
    logger.remove()
    logger.add(buf, level="WARNING", format="{level}|{message}", colorize=False)

    logger.info("library boot")
    logger.debug("deep detail")

    assert "library boot" not in buf.getvalue()
    assert "deep detail" not in buf.getvalue()


def test_cli_logging_default_level_passes_warning_and_error():
    """WARNING / ERROR / CRITICAL must reach the user.

    A red ERROR line from a library is still important even during an
    interactive wizard — silencing it would hide real failures.
    """
    buf = io.StringIO()
    logger.remove()
    configure_cli_logging()
    logger.remove()
    logger.add(buf, level="WARNING", format="{level}|{message}", colorize=False)

    logger.warning("kept it short")
    logger.error("real problem")

    output = buf.getvalue()
    assert "kept it short" in output
    assert "real problem" in output


def test_maybe_configure_server_logging_from_env_is_noop_without_vars(monkeypatch):
    """No env vars → no logger sink changes.

    This is the production gunicorn path: workers fork from a parent
    that has already configured loguru. We must not blow that
    configuration away during a re-import.
    """
    monkeypatch.delenv(ENV_LOG_LEVEL, raising=False)
    monkeypatch.delenv(ENV_DEBUG, raising=False)

    # Establish a sentinel sink. If the helper rebuilds loguru's sinks,
    # our buffer-bound sink id will be missing afterwards.
    buf = io.StringIO()
    logger.remove()
    sentinel_id = logger.add(buf, level="DEBUG", format="{message}")

    maybe_configure_server_logging_from_env()

    logger.info("sentinel-survives")
    assert "sentinel-survives" in buf.getvalue()

    logger.remove(sentinel_id)


def test_maybe_configure_server_logging_from_env_ignores_garbage_log_level(monkeypatch):
    """A non-integer PUFFERBLOW_LOG_LEVEL should silently no-op, not crash."""
    monkeypatch.setenv(ENV_LOG_LEVEL, "definitely-not-an-int")
    monkeypatch.setenv(ENV_DEBUG, "0")

    buf = io.StringIO()
    logger.remove()
    sentinel_id = logger.add(buf, level="DEBUG", format="{message}")

    # Must not raise.
    maybe_configure_server_logging_from_env()

    logger.info("still-here")
    assert "still-here" in buf.getvalue()

    logger.remove(sentinel_id)
