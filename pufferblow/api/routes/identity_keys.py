"""Identity keys: register the public key a device signs calls with, and look up other people's.

    PUT    /api/v1/identity-keys              register the caller's key (idempotent)
    GET    /api/v1/identity-keys/{user_id}    a person's keys, oldest first
    DELETE /api/v1/identity-keys/{key_id}     remove one of the caller's own keys

The instance stores and serves public keys only. Clients pin the first key they see for a person; see
``api/identity/keys.py`` for why that matters.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from pufferblow.api.database.identity_keys_mixin import IdentityKeyLimit, IdentityKeyOwnedByAnother
from pufferblow.api.dependencies import get_current_user
from pufferblow.api.errors import ApiError, ErrorCode
from pufferblow.api.identity.keys import MAX_KEYS_PER_USER, InvalidIdentityKey, to_json, validate_public_key
from pufferblow.core.bootstrap import api_initializer

router = APIRouter(prefix="/api/v1/identity-keys")


class RegisterKeyRequest(BaseModel):
    auth_token: str = Field(min_length=1)
    public_key: dict
    label: str | None = Field(default=None, max_length=64)


@router.put("", status_code=200)
async def register_identity_key(request: RegisterKeyRequest) -> dict:
    """Register the caller's public key. ``created`` is false when this exact key was already registered."""
    user_id = get_current_user(request.auth_token)
    try:
        canonical, key_id = validate_public_key(request.public_key)
    except InvalidIdentityKey as exc:
        raise ApiError(ErrorCode.VALIDATION_FIELD_RANGE, message=str(exc), details={"field": "public_key"}) from exc
    try:
        key, created = api_initializer.database_handler.register_identity_key(user_id, key_id, to_json(canonical), request.label)
    except IdentityKeyOwnedByAnother as exc:
        raise ApiError(ErrorCode.RESOURCE_CONFLICT, message="That key belongs to another account.", details={"field": "public_key"}) from exc
    except IdentityKeyLimit as exc:
        raise ApiError(
            ErrorCode.RESOURCE_CONFLICT,
            message=f"You already have {MAX_KEYS_PER_USER} keys. Remove one first.",
            details={"max": MAX_KEYS_PER_USER},
        ) from exc
    return {"status_code": 200, "created": created, "key": key}


@router.get("/{user_id}", status_code=200)
async def list_identity_keys(user_id: str, auth_token: str) -> dict:
    """A person's registered keys. Any signed-in user can read them: they are public."""
    get_current_user(auth_token)
    return {"status_code": 200, "user_id": user_id, "keys": api_initializer.database_handler.list_identity_keys(user_id)}


@router.delete("/{key_id}", status_code=200)
async def delete_identity_key(key_id: str, auth_token: str) -> dict:
    """Remove one of the caller's own keys (a lost device, say)."""
    user_id = get_current_user(auth_token)
    if not api_initializer.database_handler.delete_identity_key(user_id, key_id):
        raise ApiError(ErrorCode.RESOURCE_NOT_FOUND, message="You have no such key.", details={"key_id": key_id})
    return {"status_code": 200, "removed": True}
