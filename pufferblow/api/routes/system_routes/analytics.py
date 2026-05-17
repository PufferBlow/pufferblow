"""Chart and analytics routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from pufferblow.core.bootstrap import api_initializer

from .shared import ChartRequest, UserStatusChartRequest

router = APIRouter()


def _background_manager_or_empty():
    if not api_initializer.is_ready("background_tasks_manager"):
        return None
    return api_initializer.background_tasks_manager


def _empty_chart_response(message: str) -> dict:
    return {
        "status_code": 200,
        "message": message,
        "chart_data": {},
        "raw_stats": {},
    }


async def _chart_response(chart_type: str, period: str | None) -> dict:
    manager = _background_manager_or_empty()
    if manager is None:
        return _empty_chart_response("Background tasks manager not initialized")

    try:
        # `get_chart_data` returns the FULL envelope (chart_type,
        # period, chart_data, raw_stats, last_updated). We unwrap it
        # here so the HTTP response has a clean {chart_data, raw_stats}
        # shape — otherwise the outer `chart_data` field on the
        # response would itself be a dict containing another
        # `chart_data` array, which broke the frontend parser.
        envelope = manager.get_chart_data(chart_type, period) or {}
        chart_payload = envelope.get("chart_data", [])
        raw_stats = (
            envelope.get("raw_stats")
            or manager.get_raw_stats(chart_type, period)
            or {}
        )
        return {
            "status_code": 200,
            "chart_data": chart_payload,
            "raw_stats": raw_stats,
        }
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get {chart_type} chart data: {exc}",
        ) from exc


@router.post("/api/v1/system/charts/user-registrations", status_code=200)
async def get_user_registration_chart_route(request: ChartRequest):
    """Get user registration chart data."""
    return await _chart_response("user_registrations", request.period)


@router.post("/api/v1/system/charts/message-activity", status_code=200)
async def get_message_activity_chart_route(request: ChartRequest):
    """Get message activity chart data."""
    return await _chart_response("message_activity", request.period)


@router.post("/api/v1/system/charts/online-users", status_code=200)
async def get_online_users_chart_route(request: ChartRequest):
    """Get online users chart data."""
    return await _chart_response("online_users", request.period)


@router.post("/api/v1/system/charts/channel-creation", status_code=200)
async def get_channel_creation_chart_route(request: ChartRequest):
    """Get channel creation chart data."""
    return await _chart_response("channel_creation", request.period)


@router.post("/api/v1/system/charts/user-status", status_code=200)
async def get_user_status_chart_route(request: UserStatusChartRequest):
    """Get user status distribution chart data.

    Unlike the time-series charts, user_status is a *snapshot* —
    "how many users are online right now" — and the
    `_update_user_status_chart` task only stores it in process-local
    memory, never in the `chart_data` table. Reading from the table
    therefore always returns an empty pie. We instead read the live
    counts straight from `users.status` and shape them into the same
    {chart_data, raw_stats} envelope the time-series routes return,
    so the frontend can treat them uniformly.
    """
    try:
        status_counts = api_initializer.database_handler.get_user_status_counts() or {}
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get user status chart data: {exc}",
        ) from exc

    online = int(status_counts.get("online", 0) or 0)
    offline = int(status_counts.get("offline", 0) or 0)
    away = int(status_counts.get("away", 0) or 0)
    total = online + offline + away

    # Pie-chart shape: a list of {label, value} pairs. The frontend's
    # formatChartData maps `label` → `labels[i]` and `value` →
    # `datasets[0].data[i]` so this drops straight into the existing
    # transform without a special case.
    chart_data = [
        {"label": "Online", "value": online},
        {"label": "Offline", "value": offline},
        {"label": "Away", "value": away},
    ]

    return {
        "status_code": 200,
        "chart_data": chart_data,
        "raw_stats": {
            "online_users": online,
            "offline_users": offline,
            "away_users": away,
            "total_users": total,
        },
    }
