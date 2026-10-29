"""Who may join this server: invitation codes, and approving requests to join.

The owner and moderators hold the privileges (``manage_invites``, ``manage_join_requests``). The join mode itself is set
with the other server settings (``PUT /api/v1/system/server-info``, ``join_mode``).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body

from pufferblow.api.database.tables.activity_audit import ActivityAudit
from pufferblow.api.dependencies import require_privilege
from pufferblow.api.errors import ApiError, ErrorCode
from pufferblow.api.server.join_announce import announce_decision
from pufferblow.core.bootstrap import api_initializer

router = APIRouter(prefix="/api/v1/server")

MAX_NOTE = 120
STATUSES = ("pending", "approved", "denied")


def _audit(user_id: str, title: str, description: str, **meta) -> None:
    api_initializer.database_handler.create_activity_audit_entry(
        ActivityAudit(
            activity_id=str(uuid.uuid4()),
            activity_type="join_access_changed",
            user_id=str(user_id),
            title=title,
            description=description,
            metadata_json=json.dumps(meta),
        )
    )


# ── invitation codes ──────────────────────────────────────────


@router.get("/invites", status_code=200)
async def list_invites_route(auth_token: str):
    """Every invitation code, newest first, with how it stands (``active``, ``used_up``, ``expired`` or ``revoked``)."""
    require_privilege(auth_token, "manage_invites")
    database = api_initializer.database_handler
    return {"status_code": 200, "join_mode": database.get_join_mode(), "invites": database.list_invites()}


@router.post("/invites", status_code=201)
async def create_invite_route(
    auth_token: str = Body(..., embed=True),
    note: str | None = Body(default=None, embed=True, max_length=MAX_NOTE),
    max_uses: int | None = Body(default=None, embed=True, ge=1, le=100_000),
    expires_in_hours: int | None = Body(default=None, embed=True, ge=1, le=24 * 365),
):
    """Make an invitation code. ``max_uses`` and ``expires_in_hours`` are optional limits; without them it lasts until revoked."""
    user_id = require_privilege(auth_token, "manage_invites")
    expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours) if expires_in_hours else None
    invite = api_initializer.database_handler.create_invite(created_by=user_id, note=note, max_uses=max_uses, expires_at=expires_at)
    label = f" ({invite['note']})" if invite["note"] else ""
    _audit(user_id, "Invitation code created", f"A code was made{label}", code_tail=invite["code"][-4:], max_uses=max_uses, expires_in_hours=expires_in_hours)
    return {"status_code": 201, "invite": invite}


@router.delete("/invites/{code}", status_code=200)
async def revoke_invite_route(code: str, auth_token: str):
    """End a code now. People already in stay in."""
    user_id = require_privilege(auth_token, "manage_invites")
    if not api_initializer.database_handler.revoke_invite(code.strip().upper()):
        raise ApiError(ErrorCode.RESOURCE_NOT_FOUND, message="No such active invitation code.")
    _audit(user_id, "Invitation code revoked", "A code was revoked", code_tail=code[-4:])
    return {"status_code": 200, "revoked": True}


# ── requests to join ──────────────────────────────────────────


@router.get("/join-requests", status_code=200)
async def list_join_requests_route(auth_token: str, status: str | None = None):
    """Requests to join, newest first. ``status`` narrows to ``pending``, ``approved`` or ``denied``."""
    require_privilege(auth_token, "manage_join_requests")
    if status is not None and status not in STATUSES:
        raise ApiError(ErrorCode.VALIDATION_FIELD_RANGE, message=f"status must be one of {list(STATUSES)}.", details={"field": "status"})
    database = api_initializer.database_handler
    return {
        "status_code": 200,
        "join_mode": database.get_join_mode(),
        "pending": database.count_join_requests("pending"),
        "requests": database.list_join_requests(status),
    }


async def _decide(auth_token: str, request_id: str, status: str) -> dict:
    user_id = require_privilege(auth_token, "manage_join_requests")
    database = api_initializer.database_handler
    decided = database.decide_join_request(request_id, status=status, decided_by=user_id)
    if decided is None:
        raise ApiError(ErrorCode.RESOURCE_NOT_FOUND, message="That request doesn't exist or was already decided.", details={"request_id": request_id})
    if decided["kind"] == "local" and decided["user_id"]:
        # The account was made when they asked; this is what lets them sign in (or keeps them out).
        database.set_membership_status(decided["user_id"], "active" if status == "approved" else "denied")
    _audit(user_id, f"Request to join {status}", f"{decided['handle']}'s request to join was {status}", request_id=request_id, handle=decided["handle"], kind=decided["kind"])
    await announce_decision(decided)
    return {"status_code": 200, "request": decided, "pending": database.count_join_requests("pending")}


@router.post("/join-requests/{request_id}/approve", status_code=200)
async def approve_join_request_route(request_id: str, auth_token: str = Body(..., embed=True)):
    """Let them in. A local account can sign in at once; someone from another server gets in the next time they check."""
    return await _decide(auth_token, request_id, "approved")


@router.post("/join-requests/{request_id}/deny", status_code=200)
async def deny_join_request_route(request_id: str, auth_token: str = Body(..., embed=True)):
    """Decline. They are told the next time they try."""
    return await _decide(auth_token, request_id, "denied")
