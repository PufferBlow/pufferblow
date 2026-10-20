"""Bot management: create, list and revoke bots. Instance owner only.

A bot is an automated account that acts on behalf of its owner and can never do more than the owner
can (see ``Principal``). It authenticates with a token that is shown **once**, at creation, and is
stored only as a hash. Routes:

    POST   /api/v1/bots               create a bot, returns its token once
    GET    /api/v1/bots               list the bots (never the tokens)
    DELETE /api/v1/bots/{bot_id}      revoke a bot; its token stops working at once

Why owner only: a bot borrows its owner's standing, so who may mint one is a decision about who may
put automated actors on the instance. Bots are limited to the scopes in ``ALLOWED_BOT_SCOPES``;
administrative privileges can never be granted to one.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from pufferblow.api.bots.bot_manager import ALLOWED_BOT_SCOPES
from pufferblow.api.dependencies import require_server_owner
from pufferblow.api.errors import ApiError, ErrorCode
from pufferblow.core.bootstrap import api_initializer

router = APIRouter(prefix="/api/v1/bots")


class CreateBotRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    name: str = Field(min_length=1, max_length=64)
    #: Subset of ``send_messages`` and ``view_private_channels``. Empty means the bot can read public
    #: channels and do nothing else.
    scopes: list[str] = Field(default_factory=list)


def _public(bot) -> dict:
    return {
        "bot_id": bot.bot_id,
        "name": bot.name,
        "owner_user_id": bot.owner_user_id,
        "scopes": list(bot.scopes or []),
        "enabled": bool(bot.enabled),
        "revoked": bot.revoked_at is not None,
        "created_at": bot.created_at.isoformat() if bot.created_at else None,
    }


@router.post("", status_code=201)
async def create_bot(request: CreateBotRequest) -> dict:
    """Create a bot. The token in the response is shown once and cannot be recovered."""
    owner_id = require_server_owner(request.auth_token)
    try:
        created = api_initializer.bot_manager.create_bot(owner_id, request.name, request.scopes)
    except ValueError as exc:
        raise ApiError(
            ErrorCode.VALIDATION_FIELD_TYPE,
            user_message=str(exc),
            details={"allowed_scopes": sorted(ALLOWED_BOT_SCOPES)},
        ) from exc
    return {
        "status_code": 201,
        "message": "Bot created. Copy the token now; it is not shown again.",
        "bot": {
            "bot_id": created.identity.bot_id,
            "name": created.identity.name,
            "owner_user_id": created.identity.owner_user_id,
            "scopes": list(created.identity.scopes),
        },
        "token": created.token,
    }


@router.get("", status_code=200)
async def list_bots(auth_token: str) -> dict:
    """The instance's bots, newest first. Tokens are never returned."""
    require_server_owner(auth_token)
    return {"status_code": 200, "bots": [_public(bot) for bot in api_initializer.database_handler.list_bots()]}


@router.delete("/{bot_id}", status_code=200)
async def revoke_bot(bot_id: str, auth_token: str) -> dict:
    """Revoke a bot. Its token stops verifying immediately; open sockets are closed at the next ping."""
    require_server_owner(auth_token)
    if api_initializer.database_handler.get_bot(bot_id) is None:
        raise ApiError(ErrorCode.RESOURCE_NOT_FOUND, details={"resource": "bot", "bot_id": bot_id[:64]})
    revoked = api_initializer.bot_manager.revoke(bot_id)
    return {"status_code": 200, "message": "Bot revoked." if revoked else "Bot was already revoked.", "revoked": revoked}
