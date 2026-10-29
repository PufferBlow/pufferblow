"""Joining a server with the account you already have, from another server.

No new account and no password: the person's home server vouches for them with a short-lived signed assertion (see
``api/federation/identity_assertion.py``), and the server being joined checks it against the home server's published key.
What happens next follows the server's join mode (``api/server/join_policy.py``): let in, needs a code, or waits for a
moderator. Someone let in is a member like any other (shown as ``name@home``) and gets this server's own session tokens.

``POST /assertions``   (on your home server, signed in) asks for an assertion for a server.
``POST /join``         (on the server being joined) presents it, with an invitation code if one is needed.
``POST /join/status``  (same) asks again for a request that was pending.
``POST /leave``        (same, signed in as a member who came from elsewhere) gives the membership up.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body
from fastapi.responses import JSONResponse
from loguru import logger

from pufferblow.api.database.tables.activity_audit import ActivityAudit
from pufferblow.api.dependencies import get_current_user
from pufferblow.api.errors import ApiError, ErrorCode
from pufferblow.api.federation.identity_assertion import (
    ASSERTION_TTL_SECONDS,
    CLOCK_SKEW_SECONDS,
    AssertionInvalid,
    read_claims,
    sign_assertion,
    verify_assertion,
)
from pufferblow.api.federation.peers import host_of, normalize_host
from pufferblow.api.models.config_model import instance_id_of
from pufferblow.api.server.join_announce import announce_join_request
from pufferblow.api.server.join_policy import ACTIVE, PENDING, JoinPolicy
from pufferblow.core.bootstrap import api_initializer

router = APIRouter(prefix="/api/v1/federation")


def _ours() -> str:
    return instance_id_of(api_initializer.config).lower()


def _invalid(why: str) -> ApiError:
    # What failed is for the log; the person sees one message whatever it was.
    logger.info("Join assertion refused: {why}", why=why)
    return ApiError(ErrorCode.JOIN_ASSERTION_INVALID, message=f"Join assertion refused: {why}")


# ── on the home server ────────────────────────────────────────


@router.post("/assertions", status_code=200)
async def issue_assertion_route(auth_token: str = Body(..., embed=True), audience: str = Body(..., embed=True)):
    """A signed statement that you are who you are, for one server, good for a minute. Asked of your own home server."""
    user_id = get_current_user(auth_token)
    user = api_initializer.database_handler.get_user(user_id=user_id)
    ours = _ours()
    if str(user.origin_server).lower() != ours:
        # Only people who live here can be vouched for; a member who came from elsewhere asks their own home.
        raise ApiError(ErrorCode.AUTH_INSTANCE_MISMATCH, details={"home_server": user.origin_server})
    try:
        target = normalize_host(audience)
    except Exception as exc:
        raise ApiError(ErrorCode.VALIDATION_FIELD_RANGE, message="That isn't a server address.", details={"field": "audience"}) from exc
    if target == ours:
        raise ApiError(ErrorCode.VALIDATION_FIELD_RANGE, message="That is this server.", details={"field": "audience"})

    activitypub = api_initializer.activitypub_manager
    actor = activitypub.ensure_local_actor(user_id=str(user_id), base_url=activitypub.canonical_base_url())
    token = sign_assertion(
        private_key_pem=actor.private_key_pem,
        handle=f"{user.username}@{ours}",
        actor_uri=actor.actor_uri,
        issuer=ours,
        audience=target,
    )
    return {"status_code": 200, "assertion": token, "handle": f"{user.username}@{ours}", "audience": target, "expires_in": ASSERTION_TTL_SECONDS}


# ── on the server being joined ────────────────────────────────


async def _verified(token: str):
    """The person an assertion names and their actor, once everything about it checks out."""
    try:
        claims = read_claims(token)
    except AssertionInvalid as exc:
        raise _invalid(str(exc)) from exc

    ours = _ours()
    issuer = claims["iss"].lower()
    name, _, handle_host = claims["sub"].rpartition("@")
    if claims["aud"].lower() != ours:
        raise _invalid("for another server")
    if issuer == ours:
        raise _invalid("from this very server")
    if not name or handle_host.lower() != issuer or host_of(claims["actor"]) != issuer:
        raise _invalid("the handle, issuer and actor disagree")

    activitypub = api_initializer.activitypub_manager
    decision = activitypub.peer_policy.decide_inbound(issuer)
    if not decision.allowed:
        raise ApiError(ErrorCode.JOIN_REFUSED, message=f"Federation policy refused {issuer}: {decision.reason}")

    try:
        actor = await activitypub.fetch_remote_actor(actor_uri=claims["actor"])
    except Exception as exc:
        raise _invalid(f"the home server's key could not be fetched ({exc})") from exc
    if str(actor.preferred_username).lower() != name.lower():
        raise _invalid("the actor is not that person")

    try:
        verify_assertion(token, public_key_pem=actor.public_key_pem, audience=claims["aud"])
    except AssertionInvalid as exc:
        raise _invalid(str(exc)) from exc

    expires = datetime.fromtimestamp(claims["exp"] + CLOCK_SKEW_SECONDS, tz=timezone.utc) + timedelta(minutes=1)
    if not api_initializer.database_handler.consume_assertion_nonce(claims["nonce"], expires):
        raise _invalid("already used")
    return claims, actor


def _session_for(user_id: str) -> dict:
    """This server's own tokens for a member who came from elsewhere (their claim names this server, so the normal check passes)."""
    tokens = api_initializer.auth_token_manager.issue_session_tokens(user_id=str(user_id), origin_server=instance_id_of(api_initializer.config))
    user = api_initializer.database_handler.get_user(user_id=str(user_id))
    return {
        "status_code": 200,
        "status": "joined",
        "server_id": api_initializer.database_handler.get_server_id(),
        "user": {"user_id": str(user.user_id), "username": user.username},
        "auth_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "token_type": tokens["token_type"],
        "auth_token_expire_time": tokens["access_token_expires_at"],
        "refresh_token_expire_time": tokens["refresh_token_expires_at"],
    }


def _make_member(actor, handle: str) -> str:
    """Their account here (made on the first time, found after), switched on."""
    database = api_initializer.database_handler
    member_id = api_initializer.activitypub_manager._ensure_remote_shadow_user(actor)
    database.set_membership_status(member_id, ACTIVE)
    database.create_activity_audit_entry(
        ActivityAudit(
            activity_id=str(uuid.uuid4()),
            activity_type="user_joined",
            user_id=str(member_id),
            title=f"{handle} joined the server",
            description=f"{handle} joined with their account from {host_of(actor.actor_uri)}",
            metadata_json=json.dumps({"handle": handle, "user_id": str(member_id), "home": host_of(actor.actor_uri)}),
        )
    )
    return str(member_id)


def _is_member(actor) -> bool:
    if not actor.user_id:
        return False
    user = api_initializer.database_handler.get_user(user_id=str(actor.user_id))
    return user is not None and (getattr(user, "membership_status", "active") or "active") == ACTIVE


def _waiting(request: dict) -> JSONResponse:
    return JSONResponse(
        status_code=202,
        content={"status_code": 202, "status": "pending", "request_id": request["request_id"], "message": "Your request to join was sent. Check again later."},
    )


@router.post("/join", status_code=200)
async def join_server_route(
    assertion: str = Body(..., embed=True),
    invite_code: str | None = Body(default=None, embed=True),
    message: str | None = Body(default=None, embed=True, max_length=300),
):
    """Join this server with an account from another one. Returns this server's session tokens, or says the request is waiting."""
    claims, actor = await _verified(assertion)
    handle = claims["sub"]
    database = api_initializer.database_handler

    if _is_member(actor):
        return _session_for(str(actor.user_id))

    latest = database.latest_join_request_for(handle)
    if latest is not None and latest["kind"] == "federated":
        if latest["status"] == "pending":
            return _waiting(latest)
        if latest["status"] == "denied":
            raise ApiError(ErrorCode.AUTH_MEMBERSHIP_DENIED)
        if latest["status"] == "approved":
            return _session_for(_make_member(actor, handle))

    admission = JoinPolicy(database).admit(invite_code)
    if admission == PENDING:
        request = database.create_join_request(kind="federated", handle=handle, home_host=host_of(actor.actor_uri), actor_uri=actor.actor_uri, message=message)
        await announce_join_request(request)
        return _waiting(request)
    return _session_for(_make_member(actor, handle))


@router.post("/join/status", status_code=200)
async def join_status_route(assertion: str = Body(..., embed=True)):
    """Ask again about a request that was waiting. Returns session tokens once it was approved."""
    claims, actor = await _verified(assertion)
    handle = claims["sub"]
    if _is_member(actor):
        return _session_for(str(actor.user_id))
    latest = api_initializer.database_handler.latest_join_request_for(handle)
    if latest is None or latest["kind"] != "federated":
        return {"status_code": 200, "status": "none"}
    if latest["status"] == "pending":
        return _waiting(latest)
    if latest["status"] == "denied":
        raise ApiError(ErrorCode.AUTH_MEMBERSHIP_DENIED)
    return _session_for(_make_member(actor, handle))


@router.post("/leave", status_code=200)
async def leave_server_route(auth_token: str = Body(..., embed=True)):
    """Give up a membership you got by joining from another server. Your own server and account are untouched."""
    user_id = get_current_user(auth_token)
    database = api_initializer.database_handler
    user = database.get_user(user_id=user_id)
    if str(user.origin_server).lower() == _ours():
        raise ApiError(ErrorCode.VALIDATION_FIELD_RANGE, message="This is your home server; there is nothing to leave.", details={"field": "auth_token"})
    database.set_membership_status(user_id, "remote")
    return {"status_code": 200, "left": True}
