"""Federation admin: the mode, the peers, and the rules for each.

Admins (and the owner) decide which instances this one federates with. See
``pufferblow/api/federation/peers.py`` for what the modes, statuses and switches mean.
"""

from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Body
from loguru import logger

from pufferblow.api.database.tables.activity_audit import ActivityAudit
from pufferblow.api.dependencies import require_server_owner
from pufferblow.api.errors import ApiError, ErrorCode
from pufferblow.api.federation.nodeinfo import UnsafeHost, fetch_peer_info
from pufferblow.api.federation.peers import MODES, STATUSES, PeerError, normalize_host
from pufferblow.core.bootstrap import api_initializer

router = APIRouter(prefix="/api/v1/federation")

MAX_IMPORT = 500


def _bad(exc: PeerError) -> ApiError:
    return ApiError(ErrorCode.VALIDATION_FIELD_RANGE, message=str(exc), details={"field": exc.field})


def _host(value: str) -> str:
    try:
        return normalize_host(value)
    except PeerError as exc:
        raise _bad(exc) from exc


def _audit(user_id: str, title: str, description: str, **meta) -> None:
    api_initializer.database_handler.create_activity_audit_entry(
        ActivityAudit(
            activity_id=str(uuid.uuid4()),
            activity_type="federation_changed",
            user_id=str(user_id),
            title=title,
            description=description,
            metadata_json=json.dumps(meta),
        )
    )


def _counts(peers: list[dict]) -> dict[str, int]:
    return {status: sum(1 for p in peers if p["status"] == status) for status in STATUSES}


def _require_peer(host: str) -> dict:
    peer = api_initializer.database_handler.get_peer(host)
    if peer is None:
        raise ApiError(ErrorCode.RESOURCE_NOT_FOUND, message=f"No peer {host}.", details={"host": host})
    return peer


@router.get("/peers", status_code=200)
async def list_peers_route(auth_token: str):
    """The federation mode, every peer, and how many are in each status."""
    require_server_owner(auth_token)
    database = api_initializer.database_handler
    peers = database.list_peers()
    return {"status_code": 200, "mode": database.get_federation_mode(), "modes": list(MODES), "counts": _counts(peers), "peers": peers}


@router.put("/mode", status_code=200)
async def set_mode_route(auth_token: str = Body(..., embed=True), mode: str = Body(..., embed=True)):
    """Set the federation mode: ``open``, ``allowlist`` or ``closed``."""
    user_id = require_server_owner(auth_token)
    try:
        api_initializer.database_handler.set_federation_mode(mode)
    except PeerError as exc:
        raise _bad(exc) from exc
    _audit(user_id, f"Federation mode set to {mode}", f"The federation mode is now '{mode}'.", mode=mode)
    return {"status_code": 200, "mode": mode}


@router.post("/peers", status_code=201)
async def add_peer_route(auth_token: str = Body(..., embed=True), host: str = Body(..., embed=True), status: str = Body("federating", embed=True)):
    """Add an instance by hand (approving it, by default). 409 if it is already a peer."""
    user_id = require_server_owner(auth_token)
    clean = _host(host)
    database = api_initializer.database_handler
    try:
        peer, created = database.upsert_peer(clean, status, added_by=str(user_id))
    except PeerError as exc:
        raise _bad(exc) from exc
    if not created:
        raise ApiError(ErrorCode.RESOURCE_CONFLICT, message=f"{clean} is already a peer.", details={"host": clean, "status": peer["status"]})
    _audit(user_id, f"Peer {clean} added", f"{clean} was added as {status}.", host=clean, status=status)
    return {"status_code": 201, "peer": peer}


@router.put("/peers/{host}/status", status_code=200)
async def set_peer_status_route(host: str, auth_token: str = Body(..., embed=True), status: str = Body(..., embed=True)):
    """Accept (``federating``), ``limited``, ``blocked`` or ``pending`` for a peer."""
    user_id = require_server_owner(auth_token)
    clean = _host(host)
    _require_peer(clean)
    try:
        peer = api_initializer.database_handler.set_peer_status(clean, status)
    except PeerError as exc:
        raise _bad(exc) from exc
    _audit(user_id, f"Peer {clean} set to {status}", f"{clean} is now {status}.", host=clean, status=status)
    return {"status_code": 200, "peer": peer}


@router.put("/peers/{host}/policy", status_code=200)
async def set_peer_policy_route(host: str, auth_token: str = Body(..., embed=True), policy: dict = Body(..., embed=True)):
    """Set some of a peer's switches: ``media``, ``voice``, ``discover`` (true or false)."""
    user_id = require_server_owner(auth_token)
    clean = _host(host)
    _require_peer(clean)
    try:
        peer = api_initializer.database_handler.set_peer_policy(clean, policy)
    except PeerError as exc:
        raise _bad(exc) from exc
    _audit(user_id, f"Policy for {clean} changed", f"Switches changed for {clean}.", host=clean, policy=policy)
    return {"status_code": 200, "peer": peer}


@router.delete("/peers/{host}", status_code=200)
async def delete_peer_route(host: str, auth_token: str):
    """Forget a peer. If it federates again later it is treated as new."""
    user_id = require_server_owner(auth_token)
    clean = _host(host)
    if not api_initializer.database_handler.delete_peer(clean):
        raise ApiError(ErrorCode.RESOURCE_NOT_FOUND, message=f"No peer {clean}.", details={"host": clean})
    _audit(user_id, f"Peer {clean} removed", f"{clean} was removed.", host=clean)
    return {"status_code": 200, "removed": True}


@router.post("/peers/{host}/refresh", status_code=200)
async def refresh_peer_route(host: str, auth_token: str = Body(..., embed=True)):
    """Ask the peer what it is (software, version, users) and keep the answer. Never sends anything to a private address."""
    require_server_owner(auth_token)
    clean = _host(host)
    _require_peer(clean)
    try:
        info = await fetch_peer_info(clean)
    except UnsafeHost as exc:
        raise ApiError(ErrorCode.VALIDATION_FIELD_RANGE, message=str(exc), details={"field": "host"}) from exc
    if info is None:
        return {"status_code": 200, "found": False, "peer": api_initializer.database_handler.get_peer(clean)}
    peer = api_initializer.database_handler.set_peer_info(clean, software=info["software"], version=info["version"], users=info["users"])
    return {"status_code": 200, "found": True, "peer": peer}


@router.post("/peers/import", status_code=200)
async def import_peers_route(
    auth_token: str = Body(..., embed=True),
    hosts: list[str] = Body(..., embed=True),
    status: str = Body("blocked", embed=True),
):
    """Add a list of hosts with one status (a shared blocklist, usually). Hosts already known keep what they have.

    Returns what was added, what was skipped because it was already a peer, and what was not a valid host.
    """
    user_id = require_server_owner(auth_token)
    if status not in STATUSES:
        raise ApiError(ErrorCode.VALIDATION_FIELD_RANGE, message=f"status must be one of {list(STATUSES)}.", details={"field": "status"})
    if len(hosts) > MAX_IMPORT:
        raise ApiError(ErrorCode.VALIDATION_FIELD_RANGE, message=f"Import at most {MAX_IMPORT} hosts at a time.", details={"field": "hosts", "max": MAX_IMPORT})
    database = api_initializer.database_handler
    added: list[str] = []
    skipped: list[str] = []
    invalid: list[str] = []
    for raw in dict.fromkeys(h.strip() for h in hosts if h and h.strip() and not h.strip().startswith("#")):
        try:
            clean = normalize_host(raw)
        except PeerError:
            invalid.append(raw[:80])
            continue
        if clean in added or clean in skipped:
            continue
        _, created = database.upsert_peer(clean, status, added_by=str(user_id))
        (added if created else skipped).append(clean)
    if added:
        _audit(user_id, f"{len(added)} peers imported", f"{len(added)} hosts were added as {status}.", status=status, count=len(added))
    logger.info(f"Federation import by {user_id}: added={len(added)} skipped={len(skipped)} invalid={len(invalid)}")
    return {"status_code": 200, "added": added, "skipped": skipped, "invalid": invalid}
