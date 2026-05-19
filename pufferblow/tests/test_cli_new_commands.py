"""Unit tests for the new operator commands: migrate, doctor, backup.

These tests treat the commands as black-box CLI entrypoints driven by
typer's CliRunner and stub out the heavy bits (engine, manager,
config) so the suite doesn't need a live database. The goal is the
shapes the user sees:

  - --check returns the right exit code for the right drift state
  - doctor surfaces failures with a non-zero exit
  - backup commands emit a clear error when pg_dump is missing,
    instead of bubbling up an obscure FileNotFoundError stack

Anything that requires real DB I/O is covered by the integration
tests (conftest spins up a sqlite store); we don't duplicate that
here.
"""

from __future__ import annotations

import sys
import types

import pytest
from typer.testing import CliRunner


def _silence_loguru(monkeypatch):
    """Keep the call signature stable; the helper is now a no-op.

    Earlier revisions of these tests stubbed `configure_cli_logging`
    to keep loguru quiet. With the unified log-style CLI output the
    configurator IS what installs the stdout sink that CliRunner
    captures, so we let it run. The helper stays so individual tests
    can still take a `monkeypatch` arg via the existing call sites.
    """
    return None


def _stub_runtime(monkeypatch, *, with_manager: bool = False):
    """Stub the heavyweight runtime hooks so commands run without a real DB."""
    monkeypatch.setattr(
        "pufferblow.cli.common.load_config_or_exit",
        lambda *args, **kwargs: types.SimpleNamespace(LOGS_PATH="/tmp/test.log"),
    )
    monkeypatch.setattr(
        "pufferblow.cli.common.ensure_database_exists",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "pufferblow.cli.common.load_runtime",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "pufferblow.api.config.config_handler.ConfigHandler.resolve_database_uri",
        lambda self: "sqlite:///tmp/test.db",
    )

    if with_manager:
        manager = types.SimpleNamespace(
            config=types.SimpleNamespace(
                BACKUP_PATH="/tmp/backups",
                BACKUP_MAX_FILES=7,
                BACKUP_MIRROR_DSN=None,
            ),
            create_database_backup=None,
            mirror_database=None,
        )
        bootstrap = types.SimpleNamespace(
            api_initializer=types.SimpleNamespace(background_tasks_manager=manager)
        )
        monkeypatch.setitem(sys.modules, "pufferblow.core.bootstrap", bootstrap)
        return manager
    return None


# ── migrate ──────────────────────────────────────────────────────────


def test_migrate_check_clean_exits_zero(monkeypatch):
    """No drift → `migrate --check` reports clean and exits 0."""
    from pufferblow.cli.cli import cli

    _silence_loguru(monkeypatch)
    _stub_runtime(monkeypatch)
    monkeypatch.setattr(
        "pufferblow.cli.commands.migrate._detect_schema_drift",
        lambda: ([], []),
    )

    result = CliRunner().invoke(cli, ["migrate", "--check"])
    assert result.exit_code == 0
    assert "up to date" in result.stdout.lower()


def test_migrate_check_drift_exits_non_zero(monkeypatch):
    """Drift present → exits 1 and lists every missing table/column.

    Important for use as a deploy gate: 'pufferblow migrate --check ||
    exit 1' must fail when schema is behind.
    """
    from pufferblow.cli.cli import cli

    _silence_loguru(monkeypatch)
    _stub_runtime(monkeypatch)
    monkeypatch.setattr(
        "pufferblow.cli.commands.migrate._detect_schema_drift",
        lambda: (["new_table"], [("users", "new_col")]),
    )

    result = CliRunner().invoke(cli, ["migrate", "--check"])
    assert result.exit_code == 1
    assert "new_table" in result.stdout
    assert "users.new_col" in result.stdout


# ── doctor ──────────────────────────────────────────────────────────


def test_doctor_all_pass_exits_zero(monkeypatch):
    """Every check returning pass → exit 0 and a success Panel."""
    from pufferblow.cli.cli import cli
    from pufferblow.cli.commands import doctor as doctor_module

    _silence_loguru(monkeypatch)
    _stub_runtime(monkeypatch)

    monkeypatch.setattr(doctor_module, "_check_database", lambda uri: ("pass", "ok"))
    monkeypatch.setattr(doctor_module, "_check_schema", lambda: ("pass", "ok"))
    monkeypatch.setattr(doctor_module, "_check_storage", lambda cfg: ("pass", "ok"))
    monkeypatch.setattr(doctor_module, "_check_secrets", lambda cfg: ("pass", "ok"))
    monkeypatch.setattr(doctor_module, "_check_media_sfu", lambda cfg: ("pass", "ok"))

    # Provide a runtime config object the command can read attributes off.
    bootstrap = types.SimpleNamespace(
        api_initializer=types.SimpleNamespace(config=types.SimpleNamespace())
    )
    monkeypatch.setitem(sys.modules, "pufferblow.core.bootstrap", bootstrap)

    result = CliRunner().invoke(cli, ["doctor"])
    assert result.exit_code == 0
    assert "All checks passed" in result.stdout


def test_doctor_failure_exits_non_zero(monkeypatch):
    """Any FAIL row → exit 1, even if other rows pass.

    Warnings alone should not fail the command, but here we mix in one
    fail and expect a non-zero exit.
    """
    from pufferblow.cli.cli import cli
    from pufferblow.cli.commands import doctor as doctor_module

    _silence_loguru(monkeypatch)
    _stub_runtime(monkeypatch)

    monkeypatch.setattr(doctor_module, "_check_database", lambda uri: ("pass", "ok"))
    monkeypatch.setattr(doctor_module, "_check_schema", lambda: ("fail", "drift"))
    monkeypatch.setattr(doctor_module, "_check_storage", lambda cfg: ("pass", "ok"))
    monkeypatch.setattr(doctor_module, "_check_secrets", lambda cfg: ("warn", "missing"))
    monkeypatch.setattr(doctor_module, "_check_media_sfu", lambda cfg: ("pass", "ok"))

    bootstrap = types.SimpleNamespace(
        api_initializer=types.SimpleNamespace(config=types.SimpleNamespace())
    )
    monkeypatch.setitem(sys.modules, "pufferblow.core.bootstrap", bootstrap)

    result = CliRunner().invoke(cli, ["doctor"])
    assert result.exit_code == 1
    assert "FAIL" in result.stdout
    assert "drift" in result.stdout


def test_doctor_warn_only_still_passes(monkeypatch):
    """Warnings on their own do not fail the command.

    `media-sfu not configured` is a warning, not an error — an
    instance that doesn't run voice should still be 'healthy'.
    """
    from pufferblow.cli.cli import cli
    from pufferblow.cli.commands import doctor as doctor_module

    _silence_loguru(monkeypatch)
    _stub_runtime(monkeypatch)

    monkeypatch.setattr(doctor_module, "_check_database", lambda uri: ("pass", "ok"))
    monkeypatch.setattr(doctor_module, "_check_schema", lambda: ("pass", "ok"))
    monkeypatch.setattr(doctor_module, "_check_storage", lambda cfg: ("pass", "ok"))
    monkeypatch.setattr(doctor_module, "_check_secrets", lambda cfg: ("pass", "ok"))
    monkeypatch.setattr(doctor_module, "_check_media_sfu", lambda cfg: ("warn", "no sfu"))

    bootstrap = types.SimpleNamespace(
        api_initializer=types.SimpleNamespace(config=types.SimpleNamespace())
    )
    monkeypatch.setitem(sys.modules, "pufferblow.core.bootstrap", bootstrap)

    result = CliRunner().invoke(cli, ["doctor"])
    assert result.exit_code == 0
    assert "WARN" in result.stdout


# ── backup ──────────────────────────────────────────────────────────


@pytest.fixture
def _async_runner(monkeypatch):
    """Replace asyncio.run with a sync invoker that calls the coroutine factory.

    We want to assert which manager method was invoked; the simplest
    way is to make `asyncio.run(...)` execute the awaitable to a sync
    sentinel without spinning up a real event loop. We track calls
    instead of awaiting.
    """
    calls: list[str] = []

    def runner(coro):
        # The coroutine has a __qualname__ via its underlying function.
        name = getattr(getattr(coro, "cr_code", None), "co_name", "<unknown>")
        calls.append(name)
        coro.close()

    monkeypatch.setattr("pufferblow.cli.commands.backup.asyncio.run", runner)
    return calls


def test_backup_now_invokes_create_database_backup(monkeypatch, _async_runner):
    """`backup now` triggers the manager's pg_dump method."""
    from pufferblow.cli.cli import cli

    _silence_loguru(monkeypatch)
    manager = _stub_runtime(monkeypatch, with_manager=True)

    async def fake_backup():
        return None

    manager.create_database_backup = fake_backup

    result = CliRunner().invoke(cli, ["backup", "now"])
    assert result.exit_code == 0, result.stdout
    assert "Backup written" in result.stdout
    assert "fake_backup" in _async_runner


def test_backup_now_translates_missing_pg_dump(monkeypatch):
    """When pg_dump isn't on PATH, surface a friendly install hint.

    The stubbed asyncio.run consumes the coroutine before raising so
    pytest doesn't emit a 'coroutine was never awaited' warning.
    """
    from pufferblow.cli.cli import cli

    _silence_loguru(monkeypatch)
    manager = _stub_runtime(monkeypatch, with_manager=True)

    async def fake_backup():
        raise FileNotFoundError("pg_dump not found")

    manager.create_database_backup = fake_backup

    def raising_run(coro):
        coro.close()
        raise FileNotFoundError("pg_dump not found")

    monkeypatch.setattr("pufferblow.cli.commands.backup.asyncio.run", raising_run)

    result = CliRunner().invoke(cli, ["backup", "now"])
    assert result.exit_code == 1
    assert "pg_dump" in result.stdout
    assert "postgresql-client" in result.stdout


def test_backup_mirror_errors_when_dsn_missing(monkeypatch, _async_runner):
    """No BACKUP_MIRROR_DSN configured → fail with a setup hint."""
    from pufferblow.cli.cli import cli

    _silence_loguru(monkeypatch)
    manager = _stub_runtime(monkeypatch, with_manager=True)
    # Leave BACKUP_MIRROR_DSN as None on the stub config.

    async def fake_mirror():
        return None

    manager.mirror_database = fake_mirror

    result = CliRunner().invoke(cli, ["backup", "mirror"])
    assert result.exit_code == 1
    assert "No mirror DSN configured" in result.stdout
    # mirror_database should NOT have been invoked because we bailed
    # before calling it.
    assert "fake_mirror" not in _async_runner
