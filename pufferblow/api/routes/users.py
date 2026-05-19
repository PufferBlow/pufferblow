import json
import uuid

from fastapi import APIRouter, Body, Depends, Form, UploadFile, exceptions
from loguru import logger

from pufferblow.api.database.tables.activity_audit import ActivityAudit
from pufferblow.api.dependencies import get_current_user
from pufferblow.api.logger.msgs import info
from pufferblow.api.schemas import (
    AuthTokenQuery,
    EditProfileRequest,
    JoinServerRequest,
    ResetTokenRequest,
    SigninQuery,
    SignupRequest,
    UserProfileRequest,
)
from pufferblow.api.utils.appearance import (
    VALID_AVATAR_KINDS,
    VALID_BANNER_KINDS,
    generate_shuffle_seed,
    is_valid_hex_color,
)
from pufferblow.api.utils.is_able_to_update import is_able_to_update
from pufferblow.core.bootstrap import api_initializer

router = APIRouter(prefix="/api/v1/users")


@router.get("", status_code=200)
async def users_route():
    """Users route."""
    return {"status_code": 200, "description": "This is the main users route"}


@router.post("/signup", status_code=201)
async def signup_new_user(request: SignupRequest):
    """Signup new user."""
    if api_initializer.database_handler.get_server() is None:
        raise exceptions.HTTPException(
            status_code=503,
            detail=(
                "This instance has not been initialized. The administrator must run "
                "`pufferblow setup` before accounts can be created."
            ),
        )

    if api_initializer.user_manager.check_username(request.username):
        raise exceptions.HTTPException(
            status_code=409,
            detail="username already exists. Please change it and try again later",
        )

    user_data = api_initializer.user_manager.sign_up(
        username=request.username, password=request.password
    )

    logger.info(info.INFO_NEW_USER_SIGNUP_SUCCESSFULLY(user=user_data))

    api_initializer.database_handler.create_activity_audit_entry(
        ActivityAudit(
            activity_id=str(uuid.uuid4()),
            activity_type="user_joined",
            user_id=str(user_data.user_id),
            title=f"User {request.username} joined the server",
            description=f"New user {request.username} has successfully registered",
            metadata_json=json.dumps(
                {
                    "username": request.username,
                    "user_id": str(user_data.user_id),
                    "joined_at": user_data.created_at.isoformat(),
                }
            ),
        )
    )

    session_tokens = api_initializer.auth_token_manager.issue_session_tokens(
        user_id=str(user_data.user_id),
        origin_server=user_data.origin_server,
    )

    return {
        "status_code": 201,
        "message": "Account created successfully",
        "auth_token": session_tokens["access_token"],
        "refresh_token": session_tokens["refresh_token"],
        "token_type": session_tokens["token_type"],
        "auth_token_expire_time": session_tokens["access_token_expires_at"],
        "refresh_token_expire_time": session_tokens["refresh_token_expires_at"],
    }


@router.get("/signin", status_code=200)
async def signin_user(query: SigninQuery = Depends()):
    """Signin user."""
    if not api_initializer.user_manager.check_username(username=query.username):
        raise exceptions.HTTPException(
            status_code=404,
            detail="The provided username does not exist or could not be found. Please make sure you have entered a valid username and try again.",
        )

    user, is_signin_successful, failure_reason = api_initializer.user_manager.sign_in(
        username=query.username, password=query.password
    )
    if not is_signin_successful:
        if failure_reason == "instance_mismatch":
            raise exceptions.HTTPException(
                status_code=403,
                detail="This account belongs to a different instance and cannot sign in on this server.",
            )
        if failure_reason == "banned":
            raise exceptions.HTTPException(
                status_code=403,
                detail="This account has been banned from this home instance.",
            )
        raise exceptions.HTTPException(
            status_code=401,
            detail="The provided password is incorrect. Please try again.",
        )

    api_initializer.database_handler.create_activity_audit_entry(
        ActivityAudit(
            activity_id=str(uuid.uuid4()),
            activity_type="user_signed_in",
            user_id=str(user.user_id),
            title=f"User {query.username} signed in",
            description=f"User {query.username} successfully signed in to their account",
            metadata_json=json.dumps(
                {
                    "username": query.username,
                    "user_id": str(user.user_id),
                    "signin_method": "password",
                }
            ),
        )
    )

    session_tokens = api_initializer.auth_token_manager.issue_session_tokens(
        user_id=str(user.user_id),
        origin_server=user.origin_server,
    )
    return {
        "status_code": 200,
        "message": "Signin successfully",
        "auth_token": session_tokens["access_token"],
        "refresh_token": session_tokens["refresh_token"],
        "token_type": session_tokens["token_type"],
        "auth_token_expire_time": session_tokens["access_token_expires_at"],
        "refresh_token_expire_time": session_tokens["refresh_token_expires_at"],
    }


@router.post("/profile", status_code=200)
async def users_profile_route(request: UserProfileRequest):
    """Users profile route."""
    user_id = get_current_user(request.auth_token)
    target_user_id = request.user_id if request.user_id else user_id
    is_account_owner = api_initializer.auth_token_manager.check_users_auth_token(
        user_id=target_user_id, raw_auth_token=request.auth_token
    )
    user_data = api_initializer.user_manager.user_profile(
        user_id=target_user_id, is_account_owner=is_account_owner
    )
    return {"status_code": 200, "user_data": user_data}


@router.put("/profile", status_code=200)
async def edit_users_profile_route(request: EditProfileRequest):
    """Edit users profile route."""
    user_id = get_current_user(request.auth_token)

    if request.new_username is not None:
        if api_initializer.user_manager.check_username(username=request.new_username):
            raise exceptions.HTTPException(
                detail="username already exists. Please change it and try again later",
                status_code=409,
            )
        api_initializer.user_manager.update_username(
            user_id=user_id, new_username=request.new_username
        )
        return {"status_code": 200, "message": "username updated successfully"}

    if request.status is not None:
        try:
            normalized_status = (
                await api_initializer.websockets_manager.update_user_presence_status(
                    user_id=user_id,
                    status=request.status,
                    source="http_profile_update",
                )
            )
        except ValueError as exc:
            raise exceptions.HTTPException(status_code=422, detail=str(exc)) from exc

        return {
            "status_code": 200,
            "message": "Status updated successfully",
            "status": normalized_status,
        }

    if request.new_password is not None and request.old_password is not None:
        api_initializer.user_manager.update_user_password(
            user_id=user_id, new_password=request.new_password
        )
        return {"status_code": 200, "message": "Password updated successfully"}

    if request.about is not None:
        api_initializer.user_manager.update_user_about(user_id=user_id, new_about=request.about)
        return {"status_code": 200, "message": "About updated successfully"}

    raise exceptions.HTTPException(status_code=400, detail="No update payload was provided")


@router.post("/profile/avatar", status_code=201)
async def upload_user_avatar_route(
    auth_token: str = Form(..., description="User's authentication token"),
    file: UploadFile = Form(..., description="Avatar image file"),
):
    """Upload user avatar route."""
    user_id = get_current_user(auth_token)
    avatar_url, is_duplicate = await api_initializer.user_manager.update_user_avatar(
        user_id=user_id, avatar_file=file
    )
    return {
        "status_code": 201,
        "message": (
            "Avatar updated via existing file (duplicate detected)"
            if is_duplicate
            else "Avatar uploaded successfully"
        ),
        "avatar_url": avatar_url,
        "duplicate_status": "existing" if is_duplicate else "new",
    }


@router.post("/profile/banner", status_code=201)
async def upload_user_banner_route(
    auth_token: str = Form(..., description="User's authentication token"),
    file: UploadFile = Form(..., description="Banner image file"),
):
    """Upload user banner route."""
    user_id = get_current_user(auth_token)
    banner_url, is_duplicate = await api_initializer.user_manager.update_user_banner(
        user_id=user_id, banner_file=file
    )
    return {
        "status_code": 201,
        "message": (
            "Banner updated via existing file (duplicate detected)"
            if is_duplicate
            else "Banner uploaded successfully"
        ),
        "banner_url": banner_url,
        "duplicate_status": "existing" if is_duplicate else "new",
    }


@router.put("/profile/appearance", status_code=200)
async def update_profile_appearance_route(
    auth_token: str = Body(..., embed=True),
    avatar_kind: str | None = Body(default=None),
    banner_kind: str | None = Body(default=None),
    accent_color: str | None = Body(default=None),
    shuffle_avatar_seed: bool = Body(default=False),
):
    """Switch the viewer's appearance mode without uploading a new file.

    Body (all optional):
        avatar_kind: 'identicon' | 'image'. Use 'identicon' to revert
            from a custom upload back to the DiceBear-style identicon.
            Setting 'image' here without a previously-uploaded
            avatar_url falls back to identicon rendering client-side.
        banner_kind: 'solid' | 'image'.
        accent_color: hex '#RRGGBB' — applied when banner_kind='solid'.
            Picker UI is expected to enforce a palette, but any valid
            hex is accepted server-side.
        shuffle_avatar_seed: when true, regenerate the identicon seed
            so the same user gets a different identicon. Useful for
            the 'I don't like my default' case.
    """
    user_id = get_current_user(auth_token)

    # Validate everything up front. We want either "all valid" or "no
    # mutation" — partial application would leave the user with a
    # half-applied update that's hard to reason about.
    if avatar_kind is not None and avatar_kind not in VALID_AVATAR_KINDS:
        raise exceptions.HTTPException(
            status_code=400,
            detail=f"avatar_kind must be one of {sorted(VALID_AVATAR_KINDS)}",
        )
    if banner_kind is not None and banner_kind not in VALID_BANNER_KINDS:
        raise exceptions.HTTPException(
            status_code=400,
            detail=f"banner_kind must be one of {sorted(VALID_BANNER_KINDS)}",
        )
    if accent_color is not None and not is_valid_hex_color(accent_color):
        raise exceptions.HTTPException(
            status_code=400,
            detail="accent_color must be a '#RRGGBB' hex string",
        )

    new_seed = generate_shuffle_seed() if shuffle_avatar_seed else None

    api_initializer.database_handler.update_user_appearance(
        user_id=user_id,
        avatar_kind=avatar_kind,
        banner_kind=banner_kind,
        accent_color=accent_color,
        avatar_seed=new_seed,
    )
    return {
        "status_code": 200,
        "message": "Appearance updated",
        "avatar_kind": avatar_kind,
        "banner_kind": banner_kind,
        "accent_color": accent_color,
        "avatar_seed": new_seed,
    }


@router.post("/profile/reset-auth-token", status_code=200)
async def reset_users_auth_token_route(request: ResetTokenRequest):
    """Reset users auth token route."""
    user_id = get_current_user(request.auth_token)
    if not api_initializer.user_manager.check_user_password(
        user_id=user_id, password=request.password
    ):
        logger.info(info.INFO_RESET_USER_AUTH_TOKEN_FAILED(user_id=user_id))
        raise exceptions.HTTPException(
            detail="Incorrect password. Please try again", status_code=404
        )

    updated_at = api_initializer.database_handler.get_auth_tokens_updated_at(user_id=user_id)
    if updated_at is not None and not is_able_to_update(updated_at=updated_at, suspend_time=2):
        logger.info(info.INFO_AUTH_TOKEN_SUSPENSION_TIME(user_id=user_id))
        raise exceptions.HTTPException(
            detail="Cannot reset authentication token. Suspension time has not elapsed.",
            status_code=403,
        )

    user = api_initializer.database_handler.get_user(user_id=user_id)
    session_tokens = api_initializer.auth_token_manager.issue_session_tokens(
        user_id=user_id,
        origin_server=user.origin_server,
    )

    return {
        "status_code": 200,
        "message": "auth_token reset successfully",
        "auth_token": session_tokens["access_token"],
        "refresh_token": session_tokens["refresh_token"],
        "token_type": session_tokens["token_type"],
        "auth_token_expire_time": session_tokens["access_token_expires_at"],
        "refresh_token_expire_time": session_tokens["refresh_token_expires_at"],
    }


@router.get("/list", status_code=200)
async def list_users_route(query: AuthTokenQuery = Depends()):
    """List users route."""
    viewer_user_id = get_current_user(query.auth_token)
    users = api_initializer.user_manager.list_users(
        viewer_user_id=viewer_user_id, auth_token=query.auth_token
    )
    return {"status_code": 200, "users": users}


# ── Joined-servers (federation) ──────────────────────────────────────
#
# Each user carries a list of remote-instance host:port identifiers in
# Users.joined_servers_ids. Since the v1.0 server_id rewrite the
# server_id IS the addressable host:port, so "joining" a server now
# means appending its domain to that list — the client can talk to it
# directly via the same protocol the home instance speaks.
#
# What this endpoint pair does NOT do:
#   - Federate the user's identity to the remote server. The remote
#     doesn't yet know the user exists.
#   - Subscribe to channel-list updates. The client polls /channel/list
#     against the remote on demand.
#
# Both are roadmap items; today the server "join" is local bookkeeping
# so the client knows which remote APIs to also query. That's enough
# to make the rail render extra avatars and let the user navigate to
# their public channels.


@router.get("/joined-servers", status_code=200)
async def list_joined_servers_route(query: AuthTokenQuery = Depends()):
    """Return the caller's joined-server identifiers.

    Returns the raw list of host:port strings; the client resolves
    each to a server_info payload on its own (the home instance can
    only speak for itself).
    """
    user_id = get_current_user(query.auth_token)
    user = api_initializer.database_handler.get_user(user_id=user_id)
    if user is None:
        raise exceptions.HTTPException(status_code=404, detail="User not found")
    return {
        "status_code": 200,
        "joined_servers": list(user.joined_servers_ids or []),
        "origin_server": user.origin_server,
    }


@router.post("/joined-servers", status_code=201)
async def join_server_route(request: JoinServerRequest):
    """Join a remote Pufferblow instance.

    Validates that ``target`` is reachable and identifies itself as
    a Pufferblow server before persisting. The probe uses the
    target's public ``/api/v1/system/server-info`` endpoint — no
    secret exchange, no actor handshake. That's deliberate for v1.0:
    join semantics are "follow this server's public surface", not
    "create an account there".
    """
    user_id = get_current_user(request.auth_token)
    ok, error_code, server_info = api_initializer.user_manager.join_server(
        user_id=user_id, target=request.target
    )
    if not ok:
        status = {
            "unreachable": 502,
            "not_pufferblow": 502,
            "self_join": 409,
            "invalid_target": 400,
        }.get(error_code or "", 400)
        raise exceptions.HTTPException(
            status_code=status,
            detail={
                "code": error_code,
                "message": _join_error_message(error_code),
            },
        )

    return {
        "status_code": 201,
        "server_info": server_info,
    }


@router.post("/joined-servers/leave", status_code=200)
async def leave_server_route(request: JoinServerRequest):
    """Drop a remote instance from the caller's joined-servers list.

    Same payload shape as the join endpoint. ``target`` is the
    server_id (host:port) to drop. The home instance can't be
    dropped via this path — see UserManager.leave_server.

    Modeled as POST rather than DELETE because the body carries
    auth_token + target, and HTTP DELETE with a body is poorly
    supported across some intermediate proxies / fetch clients
    (notably the renderer's apiClient.delete which routes params
    as a query string instead of a body).
    """
    user_id = get_current_user(request.auth_token)
    ok, error_code = api_initializer.user_manager.leave_server(
        user_id=user_id, target=request.target
    )
    if not ok:
        status = {
            "cannot_leave_home": 409,
            "user_not_found": 404,
            "invalid_target": 400,
        }.get(error_code or "", 400)
        raise exceptions.HTTPException(
            status_code=status,
            detail={
                "code": error_code,
                "message": _leave_error_message(error_code),
            },
        )
    return {"status_code": 200}


def _join_error_message(code: str | None) -> str:
    """Human-readable mapping for join failures.

    Kept inline (not a util) because no other route surfaces these
    codes and the messages are tightly coupled to the route copy.
    """
    return {
        "unreachable": (
            "Could not reach that instance. Check the address and try again."
        ),
        "not_pufferblow": (
            "That host answered but doesn't look like a Pufferblow instance."
        ),
        "self_join": "You're already on this instance — you can't join your own home.",
        "invalid_target": "The instance address looks malformed.",
    }.get(code or "", "Could not join that instance.")


def _leave_error_message(code: str | None) -> str:
    return {
        "cannot_leave_home": (
            "You can't leave your home instance — that's the account "
            "you signed up on."
        ),
        "user_not_found": "That account no longer exists.",
        "invalid_target": "The instance address looks malformed.",
    }.get(code or "", "Could not leave that instance.")
