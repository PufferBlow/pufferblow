"""Database schema migration command.

Pufferblow does not use Alembic. Schema is shipped via SQLAlchemy
declarative tables plus a small set of idempotent ALTER scripts in
`database_handler.setup_tables` (the appearance-column migration, the
blocked_ips counter migration, etc.). Every `pufferblow serve` run
calls `setup_tables` during boot, so a single-process deploy with
restart-on-upgrade already gets the migration "for free".

This command exists for the cases where boot-time migration is not
what you want:

  - Multi-replica deploys where one box should apply schema before
    the others start serving traffic.
  - A nervous operator who wants to apply schema changes during a
    maintenance window, verify, and only then start the server.
  - CI pipelines that need to assert "the model and the DB agree"
    without booting a full app.

`migrate --check` reports drift between SQLAlchemy's declared
metadata and the live database (missing tables, missing columns) but
does not apply anything. The exit code is 0 if there is no drift, 1
otherwise — useful as a deploy gate.
"""

from __future__ import annotations

from loguru import logger


def _ui_error(message: str) -> None:
    logger.error(message)


def _detect_schema_drift() -> tuple[list[str], list[tuple[str, str]]]:
    """Return (missing_tables, missing_columns) by comparing models to DB.

    `missing_columns` is a list of (table_name, column_name) tuples for
    columns the SQLAlchemy declarative metadata declares but that are
    not present on the live database. We don't report columns the DB
    has but metadata doesn't — those are leftover state, not drift the
    server cares about.
    """
    from sqlalchemy import inspect

    from pufferblow.api.database.tables.declarative_base import Base
    from pufferblow.core.bootstrap import api_initializer

    inspector = inspect(api_initializer.database_handler.database_engine)
    live_tables = set(inspector.get_table_names())

    missing_tables: list[str] = []
    missing_columns: list[tuple[str, str]] = []

    for table in Base.metadata.sorted_tables:
        if table.name not in live_tables:
            missing_tables.append(table.name)
            continue
        try:
            live_cols = {col["name"] for col in inspector.get_columns(table.name)}
        except Exception:
            # If we can't introspect a single table, skip it rather than
            # erroring the whole drift check.
            continue
        for column in table.columns:
            if column.name not in live_cols:
                missing_columns.append((table.name, column.name))

    return missing_tables, missing_columns


def migrate_command(
    check: bool = False,
    backfill_search: bool = False,
    backfill_batch_size: int = 500,
) -> None:
    """Apply database schema (idempotent) or report drift in --check mode.

    With `backfill_search=True`, also walks every existing message row
    and populates its `search_tokens` tsvector from the decrypted
    plaintext. Required on long-lived instances upgrading to the ranked-
    search feature: new messages are auto-populated at write time, but
    rows that existed before the upgrade have NULL tokens and are
    invisible to search until backfilled. The operation is idempotent —
    rows with non-NULL `search_tokens` are skipped.
    """
    from pufferblow.cli.common import (
        configure_cli_logging,
        ensure_database_exists,
        load_config_or_exit,
        load_runtime,
    )

    configure_cli_logging()

    config = load_config_or_exit()
    database_uri = config.DATABASE_URI if hasattr(config, "DATABASE_URI") else None
    if not database_uri:
        from pufferblow.api.config.config_handler import ConfigHandler

        database_uri = ConfigHandler().resolve_database_uri()
    if not database_uri:
        _ui_error("No bootstrap database URI found. Run `pufferblow setup` first.")
        raise SystemExit(1)

    ensure_database_exists(database_uri)
    # `setup_tables=False` because we don't want load_runtime to
    # implicitly apply schema during the drift check. The migrate
    # command should make the apply step explicit.
    load_runtime(database_uri=database_uri, setup_tables=False)

    missing_tables, missing_columns = _detect_schema_drift()

    if check:
        if not missing_tables and not missing_columns:
            logger.success("Schema is up to date. No drift detected.")
            raise SystemExit(0)

        logger.warning(
            "Schema drift detected: {tables} missing table(s), {cols} missing column(s).",
            tables=len(missing_tables),
            cols=len(missing_columns),
        )
        for name in missing_tables:
            logger.info("  missing table   {name}", name=name)
        for table_name, column_name in missing_columns:
            logger.info(
                "  missing column  {table}.{col}", table=table_name, col=column_name
            )
        logger.info("Run `pufferblow migrate` (no --check) to apply.")
        raise SystemExit(1)

    # Non-check path: apply. Reuses the same setup_tables() that runs
    # on `pufferblow serve` boot, so behavior is byte-for-byte the
    # same as what an unattended upgrade would do.
    from pufferblow.api.database.tables.declarative_base import Base
    from pufferblow.core.bootstrap import api_initializer

    try:
        api_initializer.database_handler.setup_tables(Base)
    except Exception as exc:
        _ui_error(f"Migration failed: {exc}")
        raise SystemExit(1)

    if missing_tables:
        logger.success(
            "Created tables: {names}", names=", ".join(missing_tables)
        )
    if missing_columns:
        joined = ", ".join(f"{t}.{c}" for t, c in missing_columns)
        logger.success("Added columns: {names}", names=joined)
    if not missing_tables and not missing_columns:
        logger.success("Schema already up to date.")
        logger.info(
            "Idempotent post-migrations (appearance, blocked IP counters, backfills) ran successfully."
        )

    if backfill_search:
        _backfill_search_tokens(batch_size=max(1, int(backfill_batch_size)))


def _backfill_search_tokens(batch_size: int) -> None:
    """Walk historic messages and populate their `search_tokens` tsvector.

    Streams `messages.message_id` in batches, decrypts each plaintext via
    `MessagesManager.decrypt_message`, and issues a single transactional
    `UPDATE … SET search_tokens = to_tsvector('simple', :t) WHERE
    message_id = :id` per row. Rows whose tokens are already populated
    are skipped at SQL filter time so the command is cheap to re-run.

    No-op on SQLite (the column type degrades to plain String and the
    GIN index isn't present anyway — search on SQLite uses the
    decrypt-and-scan fallback).
    """
    import base64

    from sqlalchemy import text

    from pufferblow.core.bootstrap import api_initializer

    handler = api_initializer.database_handler
    if str(handler.database_engine.url).startswith("sqlite://"):
        logger.info("Skipping search backfill on SQLite (no tsvector column).")
        return

    messages_manager = api_initializer.messages_manager
    total_done = 0
    total_failed = 0

    with handler.database_engine.connect() as connection:
        # Count first so the progress log is meaningful. The WHERE
        # clause matches the same predicate we'll loop on; on a
        # freshly-migrated instance this might be the whole table, so
        # this is the only full-table scan we ever issue here.
        try:
            pending = connection.execute(
                text(
                    "SELECT COUNT(*) FROM messages "
                    "WHERE search_tokens IS NULL AND hashed_message IS NOT NULL"
                )
            ).scalar()
        except Exception as exc:
            _ui_error(f"Could not count messages to backfill: {exc}")
            raise SystemExit(1)

        if not pending:
            logger.success("Search backfill: nothing to do.")
            return

        logger.info(
            "Search backfill starting: {n} message(s) to index "
            "(batch size {b}).",
            n=pending,
            b=batch_size,
        )

        while True:
            try:
                rows = connection.execute(
                    text(
                        "SELECT message_id, sender_id, hashed_message "
                        "FROM messages "
                        "WHERE search_tokens IS NULL "
                        "  AND hashed_message IS NOT NULL "
                        "ORDER BY sent_at DESC "
                        "LIMIT :n"
                    ),
                    {"n": batch_size},
                ).fetchall()
            except Exception as exc:
                _ui_error(f"Backfill SELECT failed: {exc}")
                raise SystemExit(1)

            if not rows:
                break

            updates: list[dict] = []
            for row in rows:
                message_id, sender_id, hashed_message = row
                try:
                    plaintext = messages_manager.decrypt_message(
                        user_id=str(sender_id),
                        message_id=message_id,
                        encrypted_message=base64.b64decode(hashed_message),
                    )
                except Exception as exc:
                    # An undecryptable row is rare but not catastrophic
                    # — usually it means the sender's key rotation
                    # raced a federated rewrite. Leave the token NULL
                    # so the next backfill skips it cleanly, and move
                    # on.
                    total_failed += 1
                    logger.warning(
                        "Backfill skipped message_id={mid}: {err}",
                        mid=message_id,
                        err=str(exc),
                    )
                    continue

                normalized = (plaintext or "").strip()
                if not normalized:
                    continue
                updates.append({"t": normalized, "id": message_id})

            if updates:
                try:
                    with connection.begin():
                        connection.execute(
                            text(
                                "UPDATE messages "
                                "SET search_tokens = to_tsvector('simple', :t) "
                                "WHERE message_id = :id"
                            ),
                            updates,
                        )
                except Exception as exc:
                    _ui_error(f"Backfill UPDATE failed mid-batch: {exc}")
                    raise SystemExit(1)

            total_done += len(updates)
            logger.info(
                "Search backfill progress: {done}/{total} ({failed} skipped)",
                done=total_done,
                total=pending,
                failed=total_failed,
            )

    logger.success(
        "Search backfill complete: {done} indexed, {failed} skipped.",
        done=total_done,
        failed=total_failed,
    )
