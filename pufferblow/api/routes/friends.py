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
    target_user_id: str = Body(..., embed=True),
):
    """Send a friend request to `target_user_id`.

    Idempotent — if a row already exists in either direction with
    any status, the response returns that existing row instead of
    creating a duplicate. The caller can inspect `status` to
    distinguish "freshly sent" from "already pending" from "already
    friends."
    """
    actor_user_id = get_current_user(auth_token)
    if not api_initializer.user_manager.check_user(user_id=target_user_id):
        raise exceptions.HTTPException(
            status_code=404, detail="Target user not found."
        )
    try:
        row = api_initializer.friends_manager.send_request(
            requester_id=actor_user_id, addressee_id=target_user_id
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
