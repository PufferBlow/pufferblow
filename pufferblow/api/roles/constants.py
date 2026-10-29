"""Shared constants for built-in instance roles."""

OWNER_ROLE_ID = "owner"
DEFAULT_ROLE_ID = "user"
SYSTEM_ROLE_IDS = {
    OWNER_ROLE_ID,
    "moderator",
    DEFAULT_ROLE_ID,
}
IMMUTABLE_ROLE_IDS = frozenset(SYSTEM_ROLE_IDS)
#: Ids no custom role may take: the built-ins, and ``admin`` (a retired built-in; see api/database/retire_admin.py).
RESERVED_ROLE_IDS = IMMUTABLE_ROLE_IDS | {"admin"}
