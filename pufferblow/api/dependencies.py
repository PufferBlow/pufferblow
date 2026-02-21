"""
Shared dependencies for API routes.

This module contains common dependencies used across multiple routes,
such as authentication checks and permission validators.
"""

from fastapi import HTTPException
from loguru import logger

from pufferblow.api.utils.extract_user_id import extract_user_id
from pufferblow.core.bootstrap import api_initializer


def _token_preview(auth_token: str) -> str:
    """
    Return a short, non-sensitive preview for audit logs.
    """
    if not auth_token:
        return "<empty>"
    if len(auth_token) <= 8:
        return "***"
    return f"{auth_token[:4]}...{auth_token[-4:]}"


def get_current_user(auth_token: str) -> str:
    """
    Extract and validate the current user from auth token.

    Args:
        auth_token: The authentication token

    Returns:
        str: The user ID

    Raises:
        HTTPException: If auth token is invalid or user doesn't exist
    """
    logger.debug(
        "AUTH_VALIDATE_START auth_token_preview={token_preview}",
        token_preview=_token_preview(auth_token),
    )
    user_id = extract_user_id(auth_token=auth_token)

    # Verify user exists
    if not api_initializer.user_manager.check_user(
        user_id=user_id, auth_token=auth_token
    ):
        logger.warning(
            "AUTH_VALIDATE_FAILED user_id={user_id} auth_token_preview={token_preview}",
            user_id=user_id,
            token_preview=_token_preview(auth_token),
        )
        raise HTTPException(
            status_code=404,
            detail="User not found or authentication token is invalid.",
        )

    logger.info(
        "AUTH_VALIDATE_OK user_id={user_id} auth_token_preview={token_preview}",
        user_id=user_id,
        token_preview=_token_preview(auth_token),
    )
    return user_id


def require_server_owner(auth_token: str) -> str:
    """
    Require that the user is the server owner.

    Args:
        auth_token: The authentication token

    Returns:
        str: The user ID if user is server owner

    Raises:
        HTTPException: If user is not the server owner
    """
    user_id = get_current_user(auth_token)

    if not api_initializer.user_manager.is_server_owner(user_id=user_id):
        logger.warning("AUTHZ_OWNER_DENIED user_id={user_id}", user_id=user_id)
        raise HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can perform this action.",
        )

    logger.info("AUTHZ_OWNER_GRANTED user_id={user_id}", user_id=user_id)
    return user_id


def require_admin(auth_token: str) -> str:
    """
    Require that the user is an admin or server owner.

    Args:
        auth_token: The authentication token

    Returns:
        str: The user ID if user is admin or server owner

    Raises:
        HTTPException: If user is neither admin nor server owner
    """
    user_id = get_current_user(auth_token)

    is_admin = api_initializer.user_manager.is_admin(user_id=user_id)
    is_owner = api_initializer.user_manager.is_server_owner(user_id=user_id)

    if not (is_admin or is_owner):
        logger.warning(
            "AUTHZ_ADMIN_DENIED user_id={user_id} is_admin={is_admin} is_owner={is_owner}",
            user_id=user_id,
            is_admin=is_admin,
            is_owner=is_owner,
        )
        raise HTTPException(
            status_code=403,
            detail="Access forbidden. Only admins and server owners can perform this action.",
        )

    logger.info(
        "AUTHZ_ADMIN_GRANTED user_id={user_id} is_admin={is_admin} is_owner={is_owner}",
        user_id=user_id,
        is_admin=is_admin,
        is_owner=is_owner,
    )
    return user_id


def check_channel_access(user_id: str, channel_id: str) -> None:
    """
    Check if user has access to a channel (handles private channels).

    Args:
        user_id: The user's ID
        channel_id: The channel's ID

    Raises:
        HTTPException: If user doesn't have access to the channel
    """
    # Check if channel exists
    if not api_initializer.channels_manager.check_channel(channel_id=channel_id):
        logger.warning(
            "CHANNEL_ACCESS_DENIED_NOT_FOUND user_id={user_id} channel_id={channel_id}",
            user_id=user_id,
            channel_id=channel_id,
        )
        raise HTTPException(
            status_code=404,
            detail="The provided channel ID does not exist or could not be found.",
        )

    # Check if channel is private
    if api_initializer.channels_manager.is_private(channel_id=channel_id):
        # Private channels require admin or server owner access
        is_admin = api_initializer.user_manager.is_admin(user_id=user_id)
        is_owner = api_initializer.user_manager.is_server_owner(user_id=user_id)

        if not (is_admin or is_owner):
            logger.warning(
                "CHANNEL_ACCESS_DENIED_PRIVATE user_id={user_id} channel_id={channel_id} is_admin={is_admin} is_owner={is_owner}",
                user_id=user_id,
                channel_id=channel_id,
                is_admin=is_admin,
                is_owner=is_owner,
            )
            # Return 404 instead of 403 to avoid revealing private channel existence
            raise HTTPException(
                status_code=404,
                detail="The provided channel ID does not exist or could not be found.",
            )

    logger.debug(
        "CHANNEL_ACCESS_GRANTED user_id={user_id} channel_id={channel_id}",
        user_id=user_id,
        channel_id=channel_id,
    )


def get_current_user_from_node_session(session_token: str) -> str:
    """
    Resolve user identity from a decentralized node session token.
    """
    logger.debug("NODE_SESSION_INTROSPECT_START")
    session_payload = api_initializer.decentralized_auth_manager.introspect_session(
        session_token=session_token
    )
    logger.info(
        "NODE_SESSION_INTROSPECT_OK user_id={user_id} node_id={node_id}",
        user_id=session_payload.get("user_id"),
        node_id=session_payload.get("node_id"),
    )
    return session_payload["user_id"]
