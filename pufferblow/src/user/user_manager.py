import pytz
import uuid
import string
import random
import base64
import hashlib
import datetime

from loguru import logger

# Hasher
from pufferblow.src.hasher.hasher import Hasher

# AuthToken manager
from pufferblow.src.auth.auth_token_manager import AuthTokenManager

# Database handler
from pufferblow.src.database.database_handler import DatabaseHandler

# Models
from pufferblow.src.models.user_model import User
from pufferblow.src.models.keys_model import EncryptionKey
from pufferblow.src.models.config_model import Config 

# Log messages
from pufferblow.src.logger.msgs import (
    info,
    debug
)

class UserManager (object):
    """ User manager class """
    def __init__(self, database_handler: DatabaseHandler, auth_token_manager: AuthTokenManager,hasher: Hasher, config: Config) -> None:
        self.database_handler       =     database_handler
        self.auth_token_manager     =     auth_token_manager
        self.hasher                 =     hasher
        self.config                 =     config

    def sign_up(self, username: str, password: str, is_admin: bool | None = False, is_owner: bool | None = False) -> User:
        """ 
        Sign up a new user
        
        Args:
            username (str): The user's `username`.
            password (str): The user's `password`.
            is_admin (bool, default: False, Optional): Is this user going to be an admin.
            is_owner (bool, default: False, Optional): Is this uer going to be the server owner's account.

        Returns:
            User: A `User` object.
        """
        new_user = User()

        user_id                 =   self._generate_user_id(username=username)
        auth_token              =   f"{user_id}.{self.auth_token_manager.create_token()}"
        auth_token_expire_time  =   self.auth_token_manager.create_auth_token_expire_time()

        new_user.user_id                                =       user_id
        new_user.username                               =       self._encrypt_data(
            user_id=new_user.user_id,
            data=username,
            associated_to="username",
            algo_type="AES"
        )
        new_user.password                               =       self._encrypt_data(
            user_id=new_user.user_id,
            data=password,
            associated_to="password",
            algo_type="AES"
        )
        new_user.raw_auth_token                         =       auth_token
        new_user.encrypted_auth_token                   =       self._encrypt_data(
            user_id=new_user.user_id,
            data=auth_token,
            associated_to="auth_token",
            algo_type="AES"
        )
        new_user.auth_token_expire_time                 =       auth_token_expire_time
        new_user.status                                 =       "online"
        new_user.contacts                               =       []
        new_user.conversations                          =       []
        new_user.joined_servers_ids                     =       [self.database_handler.get_server_id(), ]
        new_user.is_admin                               =       is_admin
        new_user.is_owner                               =       is_owner
        new_user.created_at                             =       datetime.date.today().strftime("%Y-%m-%d")
        new_user.last_seen                              =       datetime.datetime.now(pytz.timezone("GMT")).strftime("%Y-%m-%d %H:%M:%S")
        new_user.updated_at                             =       None
        
        self.database_handler.sign_up(
            user_data=new_user
        )
        
        return new_user

    def list_users(self, viewer_user_id: str, auth_token: str) -> list:
        """
        Fetch a list of metadata about all the existing
        users in the server
        
        Args:
            `viewer_user_id` (str): The user's `user_id`.
            `auth_token` (str): The user's `auth_token`.
        
        Returns:
            list: A list of users's metadata.
        """
        users = []

        users_id = self.database_handler.get_users_id()

        for user_id in users_id:
            is_account_owner = self.auth_token_manager.check_users_auth_token(
                user_id=user_id,
                raw_auth_token=auth_token
            )

            user_data = self.user_profile(
                user_id=user_id,
                is_account_owner=is_account_owner
            )

            users.append(user_data)
        
        logger.info(
            info.INFO_REQUEST_USERS_LIST(
                viewer_user_id=viewer_user_id,
                auth_token=auth_token
            )
        )

        return users

    def user_profile(self, user_id: str, is_account_owner: bool | None = False) -> dict:
        """
        Fetch the user's profile metadata
        
        Paramters:
            `user_id` (str): The user's `user_id`.
            `is_account_owner` (bool, optional, default: False): Is this `user_id` ownes this account.
        
        Returns:
            dict: The user's profile metadata in a dict format.
        """
        user_data = self.database_handler.fetch_user_data(
            user_id=user_id,
        )

        user = User()

        user.user_id = user_data.user_id
        user.username = self._decrypt_data(
            user_id=user.user_id,
            data=user_data.username,
            associated_to="username"
        )
        user.status         =    user_data.status
        user.last_seen      =    user_data.last_seen
        user.created_at     =    user_data.created_at
        user.is_admin       =    user_data.is_admin
        user.is_owner       =    user_data.is_owner
        
        # Check if the user owns the account
        if is_account_owner:
            user.auth_token_expire_time     =       user_data.auth_token_expire_time
            user.conversations              =       user_data.conversations
            user.contacts                   =       user_data.contacts
            user.updated_at                 =       user_data.updated_at
        
        user_data = user.to_dict()

        # Cleaning up the dict
        element_to_pop = [data for data in user_data if user_data[data] == ""]
    
        for data in element_to_pop:
            user_data.pop(data)
        
        logger.info(
            info.INFO_REQUEST_USER_PROFILE(
                user_data=user_data,
                viewer_user_id=user_id
            )
        )
        
        return user_data
    
    def check_user(self, user_id: str, auth_token: str | None=None) -> bool:
        """
        Check if the user exists or not
        
        Args:
            `user_id` (str): The user's `user_id`.
            `auth_token` (str, optional, default: None): The user's `auth_token`, in case it is None, then we are expecting to check only if the `user_id` exists without the check of the user's `auth_token`.

        Returns:
            bool: True is the user exists, otherswise False.
        """
        users_id = self.database_handler.get_users_id()

        if user_id not in users_id:
            return False
        
        if auth_token is not None:
            is_users_auth_token = self.auth_token_manager.check_users_auth_token(
                user_id=user_id,
                raw_auth_token=auth_token
            )

            return is_users_auth_token
         
        return True
    
    def is_server_owner(self, user_id: str) -> bool:
        """
        Check if the user is the owner of the server or not
        
        Args:
            `user_id` (str): The user's `user_id`.
        
        Returns:
            bool: True if the user is the server owner, otherwise False
        """
        user_data = self.database_handler.fetch_user_data(
            user_id=user_id
        )

        return user_data.is_owner
    
    def is_admin(self, user_id: str) -> bool:
        """
        Check if the user is an admin of the server or not
        
        Args:
            `user_id` (str): The user's `user_id`.
        
        Returns:
            bool: True if the user is an admin, otherwise False.
        """
        user_data = self.database_handler.fetch_user_data(
            user_id=user_id
        )

        return user_data.is_admin
    
    def check_username(self, username: str) -> bool:
        """
        Check if the `username` already exists or not
        
        Args:
            `username` (str): A `username` to check its existens.
        
        Returns:
            bool: True is the username exists, otherwise False.
        """
        usernames = self.database_handler.get_usernames()

        if username in usernames:
            return True
        
        return False

    def check_user_password(self, user_id: str, password: str) -> bool:
        """
        Check if the given `password` matches the user's saved hashed `password`
        
        Args:
            `user_id` (str): The user's `user_id`.
            `password` (str): The user's `password`.
        
        Returns:
            bool: True if the given `password` matches the user's saved hashed `password`, otherwise False.
        """
        user_data = self.database_handler.fetch_user_data(
            user_id=user_id
        )
        ciphered_user_password = user_data.password

        raw_password = self._decrypt_data(
            user_id=user_id,
            associated_to="password",
            data=ciphered_user_password
        )

        if raw_password != password:
            return False
        
        return True
    
    def update_username(self, user_id: str, new_username: str) -> None:
        """ 
        Update a user's `username`
        
        Args:
            `user_id` (str): The user's `user_id`.
            `new_username` (str): The new user's `username`.
        
        Returns:
            `None`.
        """
        user_data = self.database_handler.fetch_user_data(
            user_id=user_id,
        )
        ciphered_old_username = user_data.username

        raw_old_username = self._decrypt_data(
            user_id=user_id,
            associated_to="username",
            data=ciphered_old_username
        )
        
        encrypted_new_username, key =  self.hasher.encrypt(
            data=new_username
        )

        encrypted_new_username = base64.b64encode(encrypted_new_username).decode("ascii")

        key.user_id = user_id
        key.associated_to = "username"

        # Update the username
        self.database_handler.update_username(
            user_id=user_id,
            new_username=encrypted_new_username
        )

        # Update the encryption key info in the database
        self.database_handler.update_key(
            key=key
        )

        logger.info(
            info.INFO_UPDATE_USERNAME(
                user_id=user_id,
                old_username=raw_old_username,
                new_username=new_username
            )
        )
    def update_user_status(self, user_id: str, status: str) -> None:
        """
        Update the user's `status`
        
        Args:
            `status` (str): The new status value. ["online", "offline"]
        
        Returns:
            `None`.
        """
        user_data = self.database_handler.fetch_user_data(
            user_id=user_id
        )
        # users_status = user_data.status

        if user_data.status == status:
            logger.info(
                info.INFO_USER_STATUS_UPDATE_SKIPPED(
                    user_id=user_id,
                )
            )
            return

        self.database_handler.update_user_status(
            user_id=user_id,
            status=status
        )

        logger.info(
            info.INFO_UPDATE_USER_STATUS(
                user_id=user_id,
                from_status=user_data.status,
                to_status=status
            )
        )

    def update_user_password(self, user_id: str, new_password: str) -> None:
        """ 
        Update a user's `password`
        
        Args:
            `user_id` (srt): The user's `user_id`.
            `new_password` (srt): The new user's `password`.
            `old_password` (str): The old user's `password`.
        
        Returns:
            `None`.
        """
        ciphered_new_password, key = self.hasher.encrypt(
            data=new_password
        )
        ciphered_new_password = base64.b64encode(ciphered_new_password).decode("ascii")

        key.user_id = user_id
        key.associated_to = "password"

        self.database_handler.update_key(key)
        self.database_handler.update_user_password(
            user_id=user_id,
            ciphered_new_password=ciphered_new_password
        )

        logger.info(
            info.INFO_UPDATE_USER_PASSWORD(
                user_id=user_id,
                hashed_new_password=ciphered_new_password
            )
        )

    def _encrypt_data(self, user_id: str, data: str, associated_to: str, algo_type: str) -> str:
        """
        Encrypt the given `data`
        
        Args:
            user_id` (str): The user's `user_id`.
            data` (str): The `data` to encrypt.
            associated_to` (str): What will the derived `key` will be used to encrypt ("username", "auth_token").
            algo_type` (str): Type of algorithm to use to encrypt ("AES", "bcrypt").
        
        Returns:
            str: Encrypted version of the given `data`.
        """
        ciphered_data, key  =  self.hasher.encrypt(data)

        ciphered_data = base64.b64encode(ciphered_data).decode("ascii")

        key.associated_to   =     associated_to
        key.user_id         =     user_id

        if key.associated_to == "username":
            logger.debug(
                debug.DEBUG_USERNAME_ENCRYPTED(
                    username=data,
                    encrypted_username=ciphered_data
                )
            )
        elif key.associated_to == "auth_token":
            logger.debug(
                debug.DEBUG_NEW_AUTH_TOKEN_HASHED(
                    auth_token=data,
                    hashed_auth_token=ciphered_data,
                    key=key
                )
            )
        elif key.associated_to == "password":
            logger.debug(
                debug.DEBUG_NEW_PASSWORD_HASHED(
                    password=data,
                    hashed_password=ciphered_data
                )
            )

        self.database_handler.save_keys(
            key=key
        )

        return ciphered_data
    
    def _decrypt_data(self, user_id: str, data: str, associated_to: str) -> str:
        """
        Decrypt the given `data`

        Args:
            `user_id` (str): The user's `user_id`.
            `data` (str): The `data` to decrypt.
            `associated_to` (str): What was the encryption key used to encrypt ("username").
        
        Returns:
            str: The decrypted version of the `data`.
        """
        key = self.database_handler.get_keys(
            user_id=user_id,
            associated_to=associated_to
        )
        
        data = base64.b64decode(data)

        decrypted_data = self.hasher.decrypt(
            ciphertext=data,
            key=key.key_value,
            iv=key.iv
        )

        if associated_to == "username":
            logger.debug(
                debug.DEBUG_USERNAME_DECRYPTED(
                    encrypted_username=data,
                    decrypted_username=decrypted_data
                )
            )
        
        return decrypted_data

    def _generate_user_id(self, username: str) -> str:
        """
        Generate a unique `user_id` based of the user's `username`
        
        Args:
            `username` (str): The user's `username`.
        
        Returns:
            str: The generated `user_id`.
        """
        username = f"{username}{''.join([char for char in random.choices(string.ascii_letters)])}" # Adding random charachters to the username

        hashed_username_salt = hashlib.md5(username.encode()).hexdigest()
        generated_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, hashed_username_salt)

        logger.debug(
            debug.DEBUG_NEW_USER_ID_GENERATED(
                user_id=str(generated_uuid)
            )
        )

        return str(generated_uuid)
