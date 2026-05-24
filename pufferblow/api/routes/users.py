import json
import uuid

from fastapi import APIRouter, Body, Depends, Form, UploadFile, exceptions
from loguru import logger

from pufferblow.api.database.tables.activity_audit import ActivityAudit
from pufferblow.api.dependencies import get_current_user
from pufferblow.api.errors import ApiError, ErrorCode
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


# ── Credential validation rules ──────────────────────────────────
#
# Both rules are enforced at the route layer (rather than the
# Pydantic schema) so we can raise a typed ``ApiError`` with the
# right code instead of an unstructured 422 from Pydantic. Clients
# can highlight the offending input via ``details.field``.
#
# Rules picked for v1:
#
#   * Username: 3–32 chars, ASCII letters / digits / ``._-``.
#     Same character class GitHub, Discord, and most chat apps use.
#     Case-insensitive uniqueness happens server-side in the
#     manager — these rules are about format, not collision.
#
#   * Password: 8 chars minimum. No max because forcing a max
#     pushes users into weaker patterns; we cap at 256 only as a
#     denial-of-service guard. No complexity classes — NIST 800-63B
#     deprecates the "must have a digit AND a symbol" school for
#     length-first guidance.
#
# Operators that want stricter rules can layer their own auth
# proxy / IdP in front of the instance and disable signups here.

import re

_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
_PASSWORD_MIN_LENGTH = 8
_PASSWORD_MAX_LENGTH = 256


def _validate_username_format(username: str) -> None:
    """Raise ``auth.username_invalid`` if the username doesn't match.

    Does not check uniqueness — that happens against the database
    in a separate step.
    """
    if not _USERNAME_PATTERN.match(username or ""):
        raise ApiError(
            ErrorCode.AUTH_USERNAME_INVALID,
            message=f"Username failed pattern check: {username!r}",
            details={"field": "username"},
        )


def _validate_password_strength(password: str) -> None:
    """Raise ``auth.password_too_weak`` when the password violates
    one or more rules. ``details.rules`` enumerates which checks
    failed so the client can show targeted helper text.
    """
    failed: list[str] = []
    if len(password) < _PASSWORD_MIN_LENGTH:
        failed.append("min_length")
    if len(password) > _PASSWORD_MAX_LENGTH:
        failed.append("max_length")
    if failed:
        raise ApiError(
            ErrorCode.AUTH_PASSWORD_TOO_WEAK,
            message=f"Password failed rules: {failed}",
            details={
                "field": "password",
                "rules": failed,
                "min_length": _PASSWORD_MIN_LENGTH,
                "max_length": _PASSWORD_MAX_LENGTH,
            },
        )


@router.get("", status_code=200)
async def users_route():
    """Users route."""
    return {"status_code": 200, "description": "This is the main users route"}


@router.post("/signup", status_code=201)
async def signup_new_user(request: SignupRequest):
    """Create a new account on this instance.

    Pufferblow accounts are LOCAL to the instance they're created
    on — there's no central directory. The username is unique
    within this instance and case-insensitive at the comparison
    layer. Password rules are enforced by the home server's
    configuration.

    On success returns the full session-token pair
    (`auth_token` + `refresh_token`) so the caller can sign in
    immediately without a second round-trip — the same shape
    `/signin` returns.

    Returns 409 if the username already exists, 503 if the
    administrator hasn't run `pufferblow setup` yet.
    """
    # Pre-flight: instance must have completed setup before any
    # account can be created. The friendlier user_message comes
    # from the registry default; we keep the operator-oriented
    # ``message`` for the audit log so the cause is unambiguous.
    if api_initializer.database_handler.get_server() is None:
        raise ApiError(
            ErrorCode.AUTH_SIGNUP_DISABLED,
            message=(
                "This instance has not been initialized. The administrator "
                "must run `pufferblow setup` before accounts can be created."
            ),
        )

    # Format checks happen BEFORE the uniqueness query so a clearly
    # malformed username doesn't burn a database round-trip. Both
    # raise typed errors with ``details.field`` so the client can
    # highlight the input.
    _validate_username_format(request.username)
    _validate_password_strength(request.password)

    if api_initializer.user_manager.check_username(request.username):
        raise ApiError(
            ErrorCode.AUTH_USERNAME_TAKEN,
            details={"field": "username", "username": request.username},
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
    """Sign in to this instance with a username + password.

    Accepts the credentials as query parameters — historical
    shape that predates the body convention. Clients should treat
    the password as sensitive (do not log the full URL).

    Returns the same session-token pair as `/signup`. Failure
    modes:

      - 401 — wrong password.
      - 403 — account is banned, OR the account exists but
        belongs to a different instance and this instance refuses
        to issue tokens for it.
      - 404 — username doesn't exist on this instance.
    """
    # Enumeration resistance: "username not found" and "wrong
    # password" must look identical on the wire. We collapse both
    # into ``auth.invalid_credentials`` with the same user_message.
    # The server-side ``message`` field carries the specific reason
    # for logs so operators can still debug — only the public
    # surface stays generic.
    if not api_initializer.user_manager.check_username(username=query.username):
        raise ApiError(
            ErrorCode.AUTH_INVALID_CREDENTIALS,
            message=f"Sign-in attempt for unknown username {query.username!r}",
        )

    user, is_signin_successful, failure_reason = api_initializer.user_manager.sign_in(
        username=query.username, password=query.password
    )
    if not is_signin_successful:
        if failure_reason == "instance_mismatch":
            raise ApiError(
                ErrorCode.AUTH_INSTANCE_MISMATCH,
                details={"home_server": getattr(user, "origin_server", None)},
            )
        if failure_reason == "banned":
            raise ApiError(
                ErrorCode.AUTH_USER_BANNED,
                details={"user_id": str(getattr(user, "user_id", "")) or None},
            )
        # Default branch: wrong password. Collapsed to the same
        # generic shape as "unknown username" above.
        raise ApiError(
            ErrorCode.AUTH_INVALID_CREDENTIALS,
            message=f"Sign-in attempt with wrong password for {query.username!r}",
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
    # Thread the viewer id through so the manager can apply the
    # block-privacy scrub when the target has the viewer blocked.
    # Account-owner reads bypass the scrub inside the manager.
    user_data = api_initializer.user_manager.user_profile(
        user_id=target_user_id,
        is_account_owner=is_account_owner,
        viewer_user_id=user_id,
    )
    return {"status_code": 200, "user_data": user_data}


@router.put("/profile", status_code=200)
async def edit_users_profile_route(request: EditProfileRequest):
    """Edit users profile route."""
    user_id = get_current_user(request.auth_token)

    if request.new_username is not None:
        # Format check before uniqueness query — same cost-saving
        # ordering as the signup route.
        _validate_username_format(request.new_username)
        if api_initializer.user_manager.check_username(username=request.new_username):
            raise ApiError(
                ErrorCode.AUTH_USERNAME_TAKEN,
                details={"field": "new_username", "username": request.new_username},
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
    """Upload a new avatar for the authenticated user.

    Multipart form upload. The image is deduped by content hash
    (so re-uploading the same avatar doesn't double-store), a
    32 px WebP LQIP is generated synchronously, and AVIF
    optimization is queued for the background. The response
    carries both `avatar_url` (full image) and `avatar_lqip_url`
    (low-quality placeholder) so the client can render the
    LQIP-blur preview on the next paint without a follow-up
    profile fetch.

    Size + extension limits come from the instance's
    `max_image_size_mb` / `allowed_images_extensions` settings.
    """
    from pufferblow.api.user.user_manager import _resolve_storage_lqip_url

    user_id = get_current_user(auth_token)
    avatar_url, is_duplicate = await api_initializer.user_manager.update_user_avatar(
        user_id=user_id, avatar_file=file
    )
    # Return the LQIP URL alongside the full URL so the client can
    # immediately swap to a placeholder-with-blur render of the
    # just-uploaded avatar without a second profile fetch.
    lqip_url = _resolve_storage_lqip_url(
        avatar_url, api_initializer.database_handler
    )
    return {
        "status_code": 201,
        "message": (
            "Avatar updated via existing file (duplicate detected)"
            if is_duplicate
            else "Avatar uploaded successfully"
        ),
        "avatar_url": avatar_url,
        "avatar_lqip_url": lqip_url,
        "duplicate_status": "existing" if is_duplicate else "new",
    }


@router.post("/profile/banner", status_code=201)
async def upload_user_banner_route(
    auth_token: str = Form(..., description="User's authentication token"),
    file: UploadFile = Form(..., description="Banner image file"),
):
    """Upload user banner route."""
    from pufferblow.api.user.user_manager import _resolve_storage_lqip_url

    user_id = get_current_user(auth_token)
    banner_url, is_duplicate = await api_initializer.user_manager.update_user_banner(
        user_id=user_id, banner_file=file
    )
    lqip_url = _resolve_storage_lqip_url(
        banner_url, api_initializer.database_handler
    )
    return {
        "status_code": 201,
        "message": (
            "Banner updated via existing file (duplicate detected)"
            if is_duplicate
            else "Banner uploaded successfully"
        ),
        "banner_url": banner_url,
        "banner_lqip_url": lqip_url,
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
    # Reset endpoint deliberately uses a SPECIFIC "wrong password"
    # code rather than the enumeration-safe ``invalid_credentials``
    # used by /signin. The user is authenticated and on a settings
    # page; they just typed their current password and a vague
    # message would be a UX failure here.
    if not api_initializer.user_manager.check_user_password(
        user_id=user_id, password=request.password
    ):
        logger.info(info.INFO_RESET_USER_AUTH_TOKEN_FAILED(user_id=user_id))
        raise ApiError(
            ErrorCode.AUTH_RESET_PASSWORD_WRONG,
            details={"field": "password"},
        )

    updated_at = api_initializer.database_handler.get_auth_tokens_updated_at(user_id=user_id)
    if updated_at is not None and not is_able_to_update(updated_at=updated_at, suspend_time=2):
        logger.info(info.INFO_AUTH_TOKEN_SUSPENSION_TIME(user_id=user_id))
        raise ApiError(
            ErrorCode.AUTH_RESET_COOLDOWN,
            retry_after_seconds=2,
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
