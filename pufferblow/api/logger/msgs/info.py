"""Info-level log message builders.

Same call-site contract as before — these helpers are imported as
`from ..logger.msgs import info` and called with keyword arguments
from `user_manager.py`, the rate-limit middleware, and friends. The
content has been rewritten so each line reads as a short, scannable
sentence: subject first, action verb, then the relevant identifiers
after a colon. The old pattern (`"X. User ID: '...', Param: '...'"`)
was a brittle hand-rolled key/value format that loguru couldn't index
and an operator couldn't grep cleanly.
"""

# Models
from pufferblow.api.database.tables.users import Users as User


def INFO_NEW_USER_SIGNUP_SUCCESSFULLY(user: User) -> str:
    """Log a successful signup with the new user id."""
    return f"User signed up: user_id={user.user_id}"


def INFO_REQUEST_USER_PROFILE(user_data, viewer_user_id) -> str:
    """Log a profile view (who viewed whom)."""
    target = user_data["user_id"] if isinstance(user_data, dict) else getattr(
        user_data, "user_id", "?"
    )
    return f"Profile viewed: viewer={viewer_user_id} target={target}"


def INFO_REQUEST_USERS_LIST(viewer_user_id, auth_token) -> str:
    """Log a users-list request. `auth_token` accepted but never logged."""
    _ = auth_token
    return f"Users list requested: viewer={viewer_user_id}"


def INFO_UPDATE_USERNAME(user_id, new_username, old_username) -> str:
    """Log a username change in `old → new` form."""
    return (
        f"Username changed: user_id={user_id} {old_username!r} → {new_username!r}"
    )


def INFO_UPDATE_USER_STATUS(user_id, from_status, to_status) -> str:
    """Log a presence-status change in `from → to` form."""
    return (
        f"Status changed: user_id={user_id} {from_status} → {to_status}"
    )


def INFO_USER_STATUS_UPDATE_SKIPPED(user_id) -> str:
    """Log a no-op status update (caller passed the current value)."""
    return f"Status update skipped (already current): user_id={user_id}"


def INFO_USER_STATUS_UPDATE_FAILED(user_id, status) -> str:
    """Log a rejected status update due to an out-of-range value."""
    return (
        f"Status update rejected: user_id={user_id} "
        f"status={status!r} (allowed: 'online', 'offline')"
    )


def INFO_UPDATE_USER_PASSWORD(user_id, hashed_new_password) -> str:
    """Log a password rotation WITHOUT the hash value.

    Hashed passwords are still credential-equivalent (offline crack
    target). We acknowledge the rotation happened; we don't show
    what to.
    """
    _ = hashed_new_password
    return f"Password changed: user_id={user_id}"


def INFO_UPDATE_USER_PASSWORD_FAILED(user_id) -> str:
    """Log a rejected password change (caller supplied wrong old password)."""
    return f"Password change rejected (wrong current password): user_id={user_id}"


def INFO_RESET_USER_AUTH_TOKEN(user_id, new_hashed_auth_token) -> str:
    """Log an auth-token rotation WITHOUT the new hash."""
    _ = new_hashed_auth_token
    return f"Auth token rotated: user_id={user_id}"


def INFO_RESET_USER_AUTH_TOKEN_FAILED(user_id) -> str:
    """Log a rejected auth-token rotation due to a bad password."""
    return f"Auth token rotation rejected (wrong password): user_id={user_id}"


def INFO_AUTH_TOKEN_SUSPENSION_TIME(user_id) -> str:
    """Log a rejected auth-token rotation due to the suspension window."""
    return (
        f"Auth token rotation rejected (suspension window not elapsed): "
        f"user_id={user_id}"
    )


def INFO_NEW_CHANNEL_CREATED(user_id, channel_id, channel_name) -> str:
    """Log a channel creation."""
    return (
        f"Channel created: name={channel_name!r} channel_id={channel_id} "
        f"by user_id={user_id}"
    )


def INFO_CHANNEL_DELETED(user_id, channel_id) -> str:
    """Log a channel deletion."""
    return f"Channel deleted: channel_id={channel_id} by admin user_id={user_id}"


def INFO_REQUESTED_CHANNEL_DATA(channel_id, viewer_user_id) -> str:
    """Log a channel-data view."""
    return (
        f"Channel viewed: channel_id={channel_id} viewer={viewer_user_id}"
    )


def INFO_CHANNEL_ID_NOT_FOUND(channel_id, viewer_user_id) -> str:
    """Log a miss on a channel-id lookup."""
    return (
        f"Channel not found: channel_id={channel_id} "
        f"(requested by viewer={viewer_user_id})"
    )


def INFO_CHANNEL_IS_NOT_PRIVATE(user_id, channel_id, to_add_user_id) -> str:
    """Log a rejected add-user on a non-private channel."""
    return (
        f"Add-user rejected (channel not private): "
        f"channel_id={channel_id} target_user={to_add_user_id} "
        f"by admin user_id={user_id}"
    )


def INFO_NEW_USER_ADDED_TO_PRIVATE_CHANNEL(user_id, channel_id, to_add_user_id) -> str:
    """Log a successful add to a private channel."""
    return (
        f"User added to private channel: channel_id={channel_id} "
        f"user_id={to_add_user_id} by admin user_id={user_id}"
    )


def INFO_USER_REMOVED_FROM_A_PRIVATE_CHANNEL(
    user_id, channel_id, to_remove_user_id
) -> str:
    """Log a successful remove from a private channel."""
    return (
        f"User removed from private channel: channel_id={channel_id} "
        f"user_id={to_remove_user_id} by admin user_id={user_id}"
    )


def INFO_FAILD_TO_REMOVE_USER_FROM_CHANNEL_TARGETED_USER_IS_AN_ADMIN(
    user_id, channel_id, to_remove_user_id
) -> str:
    """Log a rejected remove-user where the target is also an admin."""
    return (
        f"Remove-user rejected (target is admin): "
        f"channel_id={channel_id} target_user={to_remove_user_id} "
        f"by admin user_id={user_id}"
    )


def INFO_FAILD_TO_REMOVE_USER_FROM_CHANNEL_TARGETED_USER_IS_SERVER_OWNER(
    user_id, channel_id, to_remove_user_id
) -> str:
    """Log a rejected remove-user where the target is the server owner."""
    return (
        f"Remove-user rejected (target is server owner): "
        f"channel_id={channel_id} target_owner={to_remove_user_id} "
        f"by user_id={user_id}"
    )


def CLIENT_IP_BLOCKED(
    client_ip: str, requests_count: int, rate_limit_warnings: int
) -> str:
    """Log an IP block triggered by rate-limit warning threshold."""
    return (
        f"IP blocked (rate-limit threshold): ip={client_ip} "
        f"requests={requests_count} warnings={rate_limit_warnings}"
    )


def CLIENT_IP_BLOCKED_SQL_INJECTION(
    client_ip: str, injection_warnings: int
) -> str:
    """Log an IP block triggered by repeated SQL-injection attempts."""
    return (
        f"IP blocked (sql-injection threshold): ip={client_ip} "
        f"attempts={injection_warnings}"
    )
