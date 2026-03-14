"""Shared constants for built-in instance roles."""

OWNER_ROLE_ID = "owner"
DEFAULT_ROLE_ID = "user"
SYSTEM_ROLE_IDS = {
    OWNER_ROLE_ID,
    "admin",
    "moderator",
    DEFAULT_ROLE_ID,
}
IMMUTABLE_ROLE_IDS = frozenset(SYSTEM_ROLE_IDS)
