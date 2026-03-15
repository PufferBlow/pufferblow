"""
Ping routes — local, federated, and instance ping operations.

Endpoints
---------
    POST   /api/v1/ping/send              Send a ping (auto-routes local / federated)
    POST   /api/v1/ping/instance          Probe a remote instance for reachability
    POST   /api/v1/ping/ack/{ping_id}     Acknowledge a received ping
    GET    /api/v1/ping/history           Paginated ping history (sent + received)
    GET    /api/v1/ping/pending           Pending (unacknowledged) inbound pings
    GET    /api/v1/ping/stats             Aggregated ping statistics
    DELETE /api/v1/ping/{ping_id}         Dismiss / delete a ping record
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from loguru import logger

from pufferblow.api.dependencies import (
    ensure_user_not_timed_out,
    get_current_user,
    require_privilege,
)
from pufferblow.api.schemas import (
    PingAckRequest,
    PingData,
    PingHistoryQuery,
    PingHistoryResponse,
    PingInstanceRequest,
    PingPendingResponse,
    PingSendRequest,
    PingStatsResponse,
)
from pufferblow.core.bootstrap import api_initializer

router = APIRouter(prefix="/api/v1/ping")


def _request_base_url(request: Request) -> str:
    """Extract the canonical base URL from the incoming request."""
    return str(request.base_url).rstrip("/")


def _ping_manager():
    """Shortcut accessor for the PingManager singleton."""
    pm = api_initializer.ping_manager
    if pm is None:
        raise HTTPException(
            status_code=503,
            detail="Ping service is not available.",
        )
    return pm


# ---------------------------------------------------------------------------
# POST /api/v1/ping/send
# ---------------------------------------------------------------------------


@router.post("/send", status_code=201)
async def send_ping(body: PingSendRequest, request: Request):
    """
    Send a ping to any target.

    The target can be:
    - A local **user_id** (UUID)
    - A local **username**
    - A remote **handle** (``user@domain``)
    - A remote **actor URI** (``https://…``)

    Local targets receive a WebSocket ``ping_received`` event immediately.
    Remote targets are delivered via ActivityPub ``Ping`` activity.

    A ping expires after 5 minutes if not acknowledged.
    """
    user_id = get_current_user(body.auth_token)
    ensure_user_not_timed_out(user_id, "send pings")

    base_url = _request_base_url(request)
    pm = _ping_manager()

    try:
        result = await pm.send_ping(
            sender_id=user_id,
            target=body.target,
            base_url=base_url,
            message=body.message,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.error(f"send_ping failed: {exc}")
        raise HTTPException(status_code=500, detail="Failed to send ping.")

    return {"status_code": 201, "message": "Ping sent.", "ping": result}


# ---------------------------------------------------------------------------
# POST /api/v1/ping/instance
# ---------------------------------------------------------------------------


@router.post("/instance", status_code=200)
async def ping_instance(body: PingInstanceRequest):
    """
    HTTP health-check probe to a remote PufferBlow instance.

    Hits the remote ``/healthz`` endpoint, records the round-trip latency
    and HTTP status code, and returns the result.

    Requires the ``view_server_stats`` privilege.
    """
    user_id = require_privilege(body.auth_token, "view_server_stats")
    pm = _ping_manager()

    try:
        result = await pm.send_instance_ping(
            sender_id=user_id,
            target_instance_url=body.target_instance_url,
        )
    except Exception as exc:
        logger.error(f"ping_instance failed: {exc}")
        raise HTTPException(status_code=500, detail="Instance ping failed.")

    return {"status_code": 200, "ping": result}


# ---------------------------------------------------------------------------
# POST /api/v1/ping/ack/{ping_id}
# ---------------------------------------------------------------------------


@router.post("/ack/{ping_id}", status_code=200)
async def ack_ping(ping_id: str, body: PingAckRequest, request: Request):
    """
    Acknowledge a received ping.

    Marks the ping as ``acked``, calculates the round-trip latency, notifies
    the original sender via WebSocket, and (for federated pings) sends a
    ``PingAck`` ActivityPub activity back to the remote instance.
    """
    user_id = get_current_user(body.auth_token)
    base_url = _request_base_url(request)
    pm = _ping_manager()

    try:
        result = await pm.ack_ping(
            ping_id=ping_id,
            user_id=user_id,
            base_url=base_url,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error(f"ack_ping failed: {exc}")
        raise HTTPException(status_code=500, detail="Failed to acknowledge ping.")

    return {"status_code": 200, "message": "Ping acknowledged.", "ack": result}


# ---------------------------------------------------------------------------
# GET /api/v1/ping/history
# ---------------------------------------------------------------------------


@router.get("/history", status_code=200, response_model=PingHistoryResponse)
async def get_ping_history(query: PingHistoryQuery = Depends()):
    """
    Retrieve paginated ping history for the authenticated user.

    Use ``direction=sent`` for outgoing pings, ``direction=received`` for
    inbound pings, or ``direction=both`` (default) for the complete log.
    """
    user_id = get_current_user(query.auth_token)
    pm = _ping_manager()

    pings_raw = pm.get_ping_history(
        user_id=user_id,
        direction=query.direction,
        page=query.page,
        per_page=query.per_page,
    )

    return PingHistoryResponse(
        status_code=200,
        direction=query.direction,
        page=query.page,
        per_page=query.per_page,
        pings=[PingData(**p) for p in pings_raw],
    )


# ---------------------------------------------------------------------------
# GET /api/v1/ping/pending
# ---------------------------------------------------------------------------


@router.get("/pending", status_code=200, response_model=PingPendingResponse)
async def get_pending_pings(auth_token: str):
    """
    Return all pending (unacknowledged) inbound pings for the current user.

    Useful for clients that need to display a badge or notification count on
    initial load or reconnect.
    """
    user_id = get_current_user(auth_token)
    pm = _ping_manager()

    pings_raw = pm.get_pending_pings(user_id=user_id)

    return PingPendingResponse(
        status_code=200,
        pending_count=len(pings_raw),
        pings=[PingData(**p) for p in pings_raw],
    )


# ---------------------------------------------------------------------------
# GET /api/v1/ping/stats
# ---------------------------------------------------------------------------


@router.get("/stats", status_code=200, response_model=PingStatsResponse)
async def get_ping_stats(auth_token: str):
    """
    Return aggregated ping statistics for the authenticated user.

    Statistics include total sent/received counts, acknowledged count,
    timeout count, and average round-trip latency (for acked pings).
    """
    user_id = get_current_user(auth_token)
    pm = _ping_manager()

    stats = pm.get_ping_stats(user_id=user_id)

    return PingStatsResponse(
        status_code=200,
        user_id=user_id,
        sent_total=stats.get("sent_total", 0),
        received_total=stats.get("received_total", 0),
        acked_count=stats.get("acked_count", 0),
        timeout_count=stats.get("timeout_count", 0),
        avg_latency_ms=stats.get("avg_latency_ms"),
    )


# ---------------------------------------------------------------------------
# DELETE /api/v1/ping/{ping_id}
# ---------------------------------------------------------------------------


@router.delete("/{ping_id}", status_code=200)
async def dismiss_ping(ping_id: str, auth_token: str):
    """
    Dismiss (delete) a ping record.

    The caller must be either the sender or the recipient of the ping.
    Useful for clearing completed or expired pings from history.
    """
    user_id = get_current_user(auth_token)
    pm = _ping_manager()

    deleted = pm.dismiss_ping(ping_id=ping_id, user_id=user_id)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Ping not found or you are not authorized to delete it.",
        )

    return {"status_code": 200, "message": "Ping dismissed successfully."}
