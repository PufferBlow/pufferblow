from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from pufferblow.api.database.tables.chart_data import ChartData
from pufferblow.api.database.tables.users import Users
from pufferblow.core.bootstrap import api_initializer


def _load_test_managers(tmp_path):
    database_uri = f"sqlite:///{tmp_path / 'analytics.db'}"
    api_initializer.load_objects(database_uri=database_uri)
    database_handler = api_initializer.database_handler
    ChartData.__table__.create(bind=database_handler.database_engine, checkfirst=True)
    return database_handler, api_initializer.background_tasks_manager


def _create_user(
    database_handler,
    *,
    username: str,
    status: str,
    created_at: datetime | None = None,
    last_seen: datetime | None = None,
):
    now = datetime.now(timezone.utc)
    user = Users(
        user_id=uuid4(),
        username=username,
        password="password",
        auth_token=f"token-{username}",
        status=status,
        created_at=created_at or now,
        updated_at=now,
        last_seen=last_seen or now,
    )
    with database_handler.database_session() as session:
        session.add(user)
        session.commit()


def test_save_chart_data_entry_updates_existing_metric(tmp_path):
    database_handler, _ = _load_test_managers(tmp_path)
    snapshot_time = datetime(2026, 3, 15, 7, 34, tzinfo=timezone.utc)

    first_entry = ChartData.save_hourly_metric(
        chart_type="online_users",
        metric_name="count",
        value=1,
        timestamp=snapshot_time,
    )
    second_entry = ChartData.save_hourly_metric(
        chart_type="online_users",
        metric_name="count",
        value=4,
        timestamp=snapshot_time,
    )

    database_handler.save_chart_data_entry(first_entry)
    database_handler.save_chart_data_entry(second_entry)

    with database_handler.database_session() as session:
        rows = session.query(ChartData).all()

    assert len(rows) == 1
    assert rows[0].primary_value == 4.0
    assert rows[0].metrics["count"] == 4


def test_update_server_statistics_counts_users_without_name_error(tmp_path):
    database_handler, background_manager = _load_test_managers(tmp_path)
    now = datetime.now(timezone.utc)

    _create_user(
        database_handler,
        username="online-user",
        status="online",
        created_at=now - timedelta(days=2),
        last_seen=now,
    )
    _create_user(
        database_handler,
        username="offline-user",
        status="offline",
        created_at=now - timedelta(days=10),
        last_seen=now - timedelta(days=2),
    )

    background_manager.update_server_statistics()
    stats = background_manager.get_server_stats()

    assert stats is not None
    assert stats["users"]["total"] == 2
    assert stats["users"]["online"] == 1
    assert stats["users"]["recently_active"] == 1


def test_update_online_users_chart_uses_real_hourly_snapshots(tmp_path):
    database_handler, background_manager = _load_test_managers(tmp_path)
    now = datetime.now(timezone.utc)
    yesterday_snapshot_time = (now - timedelta(days=1)).replace(
        hour=12, minute=0, second=0, microsecond=0
    )

    _create_user(
        database_handler,
        username="currently-online",
        status="online",
        created_at=now - timedelta(days=1),
        last_seen=now,
    )

    database_handler.save_chart_data_entry(
        ChartData.save_hourly_metric(
            chart_type="online_users",
            metric_name="count",
            value=3,
            timestamp=yesterday_snapshot_time,
            additional_metrics={"hour": yesterday_snapshot_time.strftime("%H")},
        )
    )

    background_manager._update_online_users_chart()

    with database_handler.database_session() as session:
        hourly_rows = (
            session.query(ChartData)
            .filter(
                ChartData.chart_type == "online_users",
                ChartData.period_type == "hourly",
            )
            .all()
        )
        today_rollup = (
            session.query(ChartData)
            .filter(
                ChartData.chart_type == "online_users",
                ChartData.period_type == "7d",
                ChartData.time_key == now.strftime("%Y-%m-%d"),
            )
            .one()
        )
        yesterday_rollup = (
            session.query(ChartData)
            .filter(
                ChartData.chart_type == "online_users",
                ChartData.period_type == "7d",
                ChartData.time_key == (now - timedelta(days=1)).strftime("%Y-%m-%d"),
            )
            .one()
        )

    assert any(row.primary_value == 1.0 for row in hourly_rows)
    assert today_rollup.primary_value == 1.0
    assert today_rollup.metrics == {"avg_count": 1.0, "peak_count": 1, "samples": 1}
    assert yesterday_rollup.primary_value == 3.0
    assert yesterday_rollup.metrics == {
        "avg_count": 3.0,
        "peak_count": 3,
        "samples": 1,
    }
