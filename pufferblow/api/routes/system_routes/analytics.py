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
        return {
            "status_code": 200,
            "chart_data": manager.get_chart_data(chart_type, period),
            "raw_stats": manager.get_raw_stats(chart_type, period) or {},
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
    """Get user status distribution chart data."""
    return await _chart_response("user_status", None)
