"""Friend graph HTTP routes.

Thin wrapper over `FriendsManager`. Every route extracts the actor
from the auth token, hands off to the manager, and translates
`FriendsError` into the right HTTP status. The manager owns all the
invariants (no self-friend, only-addressee-accepts, etc.) so this
file stays declarative — adding a new endpoint shape is straight
copy-and-tweak.

URL layout:

  POST   /api/v1/friends/requests
            body: { target_user_id }
            -> creates a pending row from actor → target
  GET    /api/v1/friends/requests
            -> { incoming: [...], outgoing: [...] }
  POST   /api/v1/friends/requests/{friendship_id}/accept
            -> flips status to accepted (only by addressee)
  DELETE /api/v1/friends/requests/{friendship_id}
            -> cancels (sender) or rejects (addressee)
  GET    /api/v1/friends
            -> [{ friendship_id, other_user_id, status, ... }]
  DELETE /api/v1/friends/{other_user_id}
            -> unfriend by the other side's user_id (no need to
               look up the friendship_id first)
"""

from __future__ import annotations

from fastapi import APIRouter, Body, exceptions

from pufferblow.api.dependencies import get_current_user
from pufferblow.api.friends.friends_manager import FriendsError
from pufferblow.core.bootstrap import api_initializer

router = APIRouter(prefix="/api/v1/friends")


def _raise_from_friends_error(exc: FriendsError) -> None:
    """Translate a manager exception into the FastAPI exception."""
    raise exceptions.HTTPException(status_code=exc.status_code, detail=str(exc))


@router.post("/requests", status_code=201)
async def send_friend_request_route(
    auth_token: str,
    target_user_id: str | None = Body(default=None, embed=True),
    target_username: str | None = Body(default=None, embed=True),
    target_origin_server: str | None = Body(default=None, embed=True),
):
    """Send a friend request.

    Two ways to identify the target — pass EXACTLY one:

      * `target_user_id` — when the client already knows the local
        UUID (e.g. clicking "Add Friend" on a user's UserCard).
      * `target_username` + `target_origin_server` — handle form,
        used by the Friends-panel "Add Friend" modal. Pass an
        empty string or omit `target_origin_server` to mean
        "this instance"; otherwise it's resolved via WebFinger
        and a shadow `users` row is created for the remote actor
        on first add. The shadow row carries `origin_server` so
        subsequent listings render `username@remote-host` without
        a separate hydration call.

    Idempotent — if a row already exists in either direction with
    any status, the response returns that existing row instead of
    creating a duplicate. Inspect `friendship.status` to know whether
    the action moved the graph.
    """
    actor_user_id = get_current_user(auth_token)

    # Resolve the target — either by id (local only) or by handle
    # (local OR remote via WebFinger).
    resolved_target_user_id: str | None = None
    if target_user_id:
        if not api_initializer.user_manager.check_user(user_id=target_user_id):
            raise exceptions.HTTPException(
                status_code=404, detail="Target user not found."
            )
        resolved_target_user_id = target_user_id
    elif target_username:
        # Handle path. `target_origin_server` empty / None / matching
        # this instance's host resolves locally; anything else is a
        # WebFinger lookup.
        resolved_target_user_id = (
            await api_initializer.activitypub_manager.resolve_user_id_for_handle(
                username=target_username,
                origin_server=target_origin_server,
                # Canonical base-URL builder. The earlier `_base_url`
                # private helper was renamed to `build_base_url`;
                # without the request's own base URL handy here we
                # let the builder fall back to the config-derived
                # canonical URL.
                base_url=api_initializer.activitypub_manager.build_base_url(),
            )
        )
        if not resolved_target_user_id:
            raise exceptions.HTTPException(
                status_code=404,
                detail=(
                    f"Could not find {target_username}"
                    + (f"@{target_origin_server}" if target_origin_server else "")
                    + " — check the spelling and instance."
                ),
            )
    else:
        raise exceptions.HTTPException(
            status_code=400,
            detail="Provide either target_user_id, or target_username (+ optional target_origin_server).",
        )

    try:
        row = api_initializer.friends_manager.send_request(
            requester_id=actor_user_id, addressee_id=resolved_target_user_id
        )
    except FriendsError as exc:
        _raise_from_friends_error(exc)
    return {
        "status_code": 201,
        "friendship": row.to_dict(),
    }


@router.get("/requests", status_code=200)
async def list_friend_requests_route(auth_token: str):
    """List the actor's incoming + outgoing pending requests.

    Split by direction so the UI can label each section without
    re-deriving from `requester_id` / `addressee_id` on every render.
    """
    actor_user_id = get_current_user(auth_token)
    payload = api_initializer.friends_manager.list_pending(
        user_id=actor_user_id
    )
    return {
        "status_code": 200,
        "incoming": payload["incoming"],
        "outgoing": payload["outgoing"],
    }


@router.post("/requests/{friendship_id}/accept", status_code=200)
async def accept_friend_request_route(friendship_id: str, auth_token: str):
    """Accept a pending request the actor received.

    Only the addressee can accept. Manager raises 403 otherwise.
    """
    actor_user_id = get_current_user(auth_token)
    try:
        row = api_initializer.friends_manager.accept_request(
            friendship_id=friendship_id, actor_user_id=actor_user_id
        )
    except FriendsError as exc:
        _raise_from_friends_error(exc)
    return {
        "status_code": 200,
        "friendship": row.to_dict(),
    }


@router.delete("/requests/{friendship_id}", status_code=200)
async def cancel_or_reject_friend_request_route(
    friendship_id: str, auth_token: str
):
    """Cancel (if actor is sender) or reject (if actor is recipient).

    Either side can call this — semantics differ only by perspective,
    but the resulting state is identical: the row is gone.
    """
    actor_user_id = get_current_user(auth_token)
    try:
        deleted = api_initializer.friends_manager.delete_relationship(
            friendship_id=friendship_id, actor_user_id=actor_user_id
        )
    except FriendsError as exc:
        _raise_from_friends_error(exc)
    return {
        "status_code": 200,
        "deleted": bool(deleted),
    }


@router.get("", status_code=200)
async def list_friends_route(auth_token: str):
    """Return the actor's accepted friends.

    Each entry includes `other_user_id` (the side of the pair that
    isn't the actor) so the client doesn't have to compare against
    its own id row-by-row to render the list.
    """
    actor_user_id = get_current_user(auth_token)
    friends = api_initializer.friends_manager.list_friends(
        user_id=actor_user_id
    )
    return {
        "status_code": 200,
        "friends": friends,
    }


@router.delete("/{other_user_id}", status_code=200)
async def unfriend_route(other_user_id: str, auth_token: str):
    """Unfriend a user by their user_id.

    Idempotent — returns `{ "removed": false }` if there was no
    accepted relationship to remove (lets the client treat
    "unfriend a stranger" the same as "unfriend a friend").
    """
    actor_user_id = get_current_user(auth_token)
    removed = api_initializer.friends_manager.unfriend(
        actor_user_id=actor_user_id, other_user_id=other_user_id
    )
    return {
        "status_code": 200,
        "removed": bool(removed),
    }


# ─────────────────────────────────────────────
# Friend-request blocks
# ─────────────────────────────────────────────


@router.post("/blocks", status_code=201)
async def block_friend_requests_route(
    auth_token: str,
    target_user_id: str = Body(..., embed=True),
):
    """Block incoming friend requests from `target_user_id`.

    Side effects: any pending request from `target_user_id` →
    actor is deleted in the same transaction so the actor's inbox
    reflects the block immediately. Accepted friendships are left
    intact — the user can call `DELETE /friends/{id}` separately
    if they want to also end the friendship.
    """
    actor_user_id = get_current_user(auth_token)
    if not api_initializer.user_manager.check_user(user_id=target_user_id):
        raise exceptions.HTTPException(
            status_code=404, detail="Target user not found."
        )
    try:
        row = api_initializer.friends_manager.block_user(
            blocker_id=actor_user_id, blocked_id=target_user_id
        )
    except FriendsError as exc:
        _raise_from_friends_error(exc)
    return {
        "status_code": 201,
        "block": row.to_dict(),
    }


@router.delete("/blocks/{blocked_user_id}", status_code=200)
async def unblock_friend_requests_route(
    blocked_user_id: str, auth_token: str
):
    """Lift a friend-request block. Idempotent."""
    actor_user_id = get_current_user(auth_token)
    removed = api_initializer.friends_manager.unblock_user(
        blocker_id=actor_user_id, blocked_id=blocked_user_id
    )
    return {
        "status_code": 200,
        "removed": bool(removed),
    }


@router.get("/blocks", status_code=200)
async def list_friend_request_blocks_route(auth_token: str):
    """Return every user the actor has blocked from sending requests.

    Used by the client's Blocked tab to render the unblock list.
    """
    actor_user_id = get_current_user(auth_token)
    blocks = api_initializer.friends_manager.list_blocks(
        blocker_id=actor_user_id
    )
    return {
        "status_code": 200,
        "blocks": blocks,
    }
