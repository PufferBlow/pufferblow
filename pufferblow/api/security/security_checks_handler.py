from fastapi.responses import ORJSONResponse
from loguru import logger

from pufferblow.api.auth.auth_token_manager import AuthTokenManager
from pufferblow.api.channels.channels_manager import ChannelsManager
from pufferblow.api.database.database_handler import DatabaseHandler

# Models
from pufferblow.api.user.user_manager import UserManager

# Utils
from pufferblow.api.utils.extract_user_id import extract_user_id
from pufferblow.api.utils.is_able_to_update import is_able_to_update
from pufferblow.api.user.status import SUPPORTED_USER_STATUSES, normalize_user_status


class SecurityChecksHandler:
    """
    This class handles all the security checks
    """

    def __init__(
        self,
        database_handler: DatabaseHandler,
        channels_manager: ChannelsManager,
        user_manager: UserManager,
        auth_token_manager: AuthTokenManager,
    ) -> None:
        """Initialize the instance."""
        self.database_handler = database_handler
        self.channels_manager = channels_manager
        self.user_manager = user_manager
        self.auth_token_manager = auth_token_manager

    def check_user_id(self, user_id: str) -> None:
        """
        Checks if the user_id exists or not, an HTTPException will be raised if not.

        Args:
            user_id (str): The user's user_id.

        Returns:
            None.
        """
        if not self.user_manager.check_user(user_id=user_id):
            return ORJSONResponse(
                status_code=404,
                content={
                    "error": f"The target user's user_id='{user_id}' not found. Please make sure to pass the correct one"
                },
            )

    def check_user(
        self, auth_token: str | None = None, user_id: str | None = None
    ) -> None:
        """
        Checks if a user exists or not, if not an HTTPException will be raised.

        Args:
            auth_token (str, optional, default: None): The user's auth_token.
            user_id (str, optional, default: None): The user's user_id, if None then it will be extracted from the auth_token.

        Returns:
            None.
        """
        logger.debug(
            f"Security check_user called with auth_token_provided={auth_token is not None}, user_id_provided={user_id is not None}"
        )

        if user_id is None:
            user_id = extract_user_id(auth_token)
            logger.debug(f"Extracted user_id from auth_token: {user_id}")

        # When both auth_token and user_id are provided, we need to validate both token ownership and user existence
        if auth_token is not None:
            # First validate the auth token belongs to this user
            token_valid = self.auth_token_manager.check_users_auth_token(
                user_id=user_id, raw_auth_token=auth_token
            )
            logger.debug(
                f"Token ownership validation for user_id={user_id}: {'PASSED' if token_valid else 'FAILED'}"
            )

            if not token_valid:
                logger.warning(
                    f"Authentication failed: invalid token for user_id={user_id}"
                )
                return ORJSONResponse(
                    status_code=404,
                    content={
                        "error": "'auth_token' expired/unvalid or 'user_id' doesn't exists. Please try again."
                    },
                )

        # Then check if the user_id exists
        if user_id is not None:
            user_exists = self.user_manager.check_user(user_id=user_id)
            logger.debug(
                f"User existence validation for user_id={user_id}: {'PASSED' if user_exists else 'FAILED'}"
            )

            if not user_exists:
                logger.warning(
                    f"Authentication failed: user_id does not exist: {user_id}"
                )
                return ORJSONResponse(
                    status_code=404,
                    content={
                        "error": f"The target user's user_id='{user_id}' not found. Please make sure to pass the correct one"
                    },
                )

        logger.debug(f"User authentication check passed for user_id={user_id}")

    def check_auth_token_format(
        self, auth_token: str, check_user_existence: bool | None = True
    ) -> None:
        """
        Checks if the auth_token's format is valid, if not it will raise
        an HTTPException.

        Args:
            auth_token (str): The user's auth_token.

        Returns:
            None.
        """
        if not self.auth_token_manager.check_auth_token_format(auth_token=auth_token):
            return ORJSONResponse(
                content={
                    "error": "Bad auth_token format. Please check your auth_token and try again."
                },
                status_code=400,
            )

    def check_username_existence(self, username: str) -> None:
        """
        Checks if the username already exists, if that's the case
        then an HTTPException will be raised.

        Args:
            username (str): The user's username to check.

        Returns:
            None.
        """
        if self.user_manager.check_username(username=username):
            return ORJSONResponse(
                content={
                    "error": "username already exists. Please change it and try again later"
                },
                status_code=409,
            )

    def check_user_status_value(self, status: str) -> None:
        """
        Checks if the status contains the supported values, it not then
        an HTTPException will be raised.

        Args:
            status (str) The status value to check.

        Returns:
            None.
        """
        try:
            normalize_user_status(status)
        except ValueError:
            # logger.info(
            #     info.INFO_USER_STATUS_UPDATE_FAILED(
            #         user_id=user_id,
            #         status=status
            #     )
            # )

            return ORJSONResponse(
                content={
                    "error": (
                        f"status value status='{status}' not found. Accepted values "
                        f"{list(SUPPORTED_USER_STATUSES)}"
                    )
                },
                status_code=404,
            )

    def check_user_password(
        self, password: str, user_id: str | None = None, auth_token: str | None = None
    ) -> None:
        """
        Checks if the user's password is correct or not, it not then
        an HTTPException will be raised.

        Args:
            user_id (str): The user's user_id.
            password (str): The user's password.

        Returns:
            None.
        """
        if user_id is None:
            user_id = extract_user_id(auth_token)

        if not self.user_manager.check_user_password(
            user_id=user_id, password=password
        ):
            # logger.info(
            #     info.INFO_UPDATE_USER_PASSWORD_FAILED(
            #         user_id=user_id
            #     )
            # )

            return ORJSONResponse(
                content={"error": "Invalid password. Please try again later."},
                status_code=401,
            )

    def check_user_suspended(self, user_id: str) -> None:
        """
        Checks if the user if suspende from reseting their auth_token,
        if that's the case then an HTTPException will be raised.

        Args:
            user_id (str): The user's user_id.

        Returns:
            None.
        """
        updated_at = self.database_handler.get_auth_tokens_updated_at(user_id=user_id)

        if not is_able_to_update(updated_at=updated_at, suspend_time=2):  # Two days
            # logger.info(
            #     info.INFO_AUTH_TOKEN_SUSPENSION_TIME(
            #         user_id=user_id
            #     )
            # )

            return ORJSONResponse(
                content={
                    "error": "Cannot reset authentication token. Suspension time has not elapsed."
                },
                status_code=403,
            )

    def check_user_privilege(
        self,
        user_id: str,
        check_if_server_owner: bool | None = True,
        check_if_admin: bool | None = True,
    ) -> None:
        """
        Checks if the user is privileged weither that be he is an admin or the server the owner, if not then an HTTPException will
        be raised.

        Args:
            user_id (str): The user's user_id.
            check_if_server_owner (bool, optional, default: True): Check if the user is the sever owner.
            check_if_admin (bool, optional, default: True): Check if the user is an admin.

        Returns:
            None.
        """
        if (check_if_admin and not self.user_manager.is_admin(user_id=user_id)) or (
            check_if_server_owner
            and not self.user_manager.is_server_owner(user_id=user_id)
        ):
            return ORJSONResponse(
                status_code=403,
                content={
                    "error": "Access forbidden. Only the server owner and admins can access this route"
                },
            )

    def check_channel_id(self, channel_id: str) -> None:
        """
        Checks if a channel_id is valid or not, if not then
        an HTTPException will be raised.

        Args:
            channel_id (str): The channel's channel_id.

        Returns:
            None.
        """
        if not self.channels_manager.check_channel(channel_id=channel_id):
            # logger.info(
            #     info.INFO_CHANNEL_ID_NOT_FOUND(
            #         viewer_user_id=user_id,
            #         channel_id=channel_id
            #     )
            # )

            return ORJSONResponse(
                status_code=404,
                content={
                    "error": "The provided channel ID does not exist or could not be found. Please make sure you have entered a valid channel ID and try again."
                },
            )

    def check_channel_name(self, channel_name: str) -> None:
        """
        Checks if the channel_name already exists or not, it that's the case then
        an HTTPException will be raised.

        Args:
            channel_name (str): The channel's channel_name.

        Returns:
            None.
        """
        channels_names = self.database_handler.get_channels_names()

        if channel_name in channels_names:
            return ORJSONResponse(
                status_code=409,
                content={
                    "error": "Channel name already exists, please change it and try again."
                },
            )

    def check_message_id(self, message_id: str) -> None:
        """
        Checks if a message exists based on its message_id, if not
        then an HTTPException will be returned.

        Args:
            message_id (str): The message's message_id.

        Returns:
            None.
        """
        if not self.messages_manager.check_message(message_id=message_id):
            return ORJSONResponse(
                content={
                    "error": "The provided `message_id` is not valid or it doesn't exists, please change it and try again."
                },
                status_code=404,
            )
