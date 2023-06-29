import pytz
import base64
import string
import random
import datetime

from loguru import logger

from pufferblow_api import constants
from pufferblow_api.src.hasher.hasher import Hasher
from pufferblow_api.src.models.user_model import User
from pufferblow_api.src.auth.auth_token_manager import AuthTokenManager
from pufferblow_api.src.database.database_handler import DatabaseHandler
from pufferblow_api.src.models.encryption_key_model import EncryptionKey

class UserManager (object):
    """ User manager class """
    def __init__(self, database_handler: DatabaseHandler, auth_token_manager: AuthTokenManager,hasher: Hasher) -> None:
        self.database_handler   =     database_handler
        self.auth_token_manager =     auth_token_manager
        self.hasher             =     hasher
    
    def sign_up(self, username: str, password: str) -> User:
        """ 
        Signs up a new user
        
        Parameters:
            username (str): The user's username
            password (str): The user's password
        """
        new_user = User()

        user_id                 =   self._generate_user_id()
        auth_token              =   self.auth_token_manager.create_token()
        auth_token_expire_time  =   self.auth_token_manager.auth_token_expire_time()

        new_user.user_id                                =       user_id
        new_user.username                               =       self._encrypt_data(
            user_id=new_user.user_id,
            data=username,
            associated_to="username",
            algo_type="blowfish"
        )
        new_user.password_hash                          =       self._encrypt_data(
            user_id=new_user.user_id,
            data=password,
            associated_to="password",
            algo_type="bcrypt"
        )
        new_user.raw_auth_token                         =       auth_token
        new_user.encrypted_auth_token                   =       self._encrypt_data(
            user_id=new_user.user_id,
            data=auth_token,
            associated_to="auth_token",
            algo_type="bcrypt"
        )
        new_user.auth_token_expire_time                 =       auth_token_expire_time
        new_user.status                                 =       "online"
        new_user.contacts                               =       []
        new_user.conversations                          =       []
        new_user.created_at                             =       datetime.date.today().strftime("%Y-%m-%d")
        new_user.last_seen                              =       datetime.datetime.now(pytz.timezone("GMT")).strftime("%Y-%m-%d %H:%M:%S")

        self.database_handler.sign_up(
            user_data=new_user
        )
        
        return new_user

    def user_profile(self, user_id: str, hashed_auth_token: str) -> dict:
        """
        Returns the user's profile data
        
        Paramters:
            user_id (str): The user's `user_id`
            hashed_auth_token (str): The hashed user's `auth_token`
        
        Returns:
            dict: The user's profile data in a dict format
        """
        user_data = self.database_handler.fetch_user_data(
            user_id=user_id,
        )

        encrypted_username              =       user_data[1]
        hashed_user_auth_token          =       user_data[7]
        auth_token_expire_time          =       user_data[8]

        status      =   user_data[3]
        last_seen   =   user_data[4]
        created_at  =   user_data[9]
        updated_at  =   user_data[10]

        conversations   =   user_data[5]
        contacts        =   user_data[6]

        user = User()

        user.user_id = user_id
        user.username = self._decrypt_data(
            user_id=user.user_id,
            data=encrypted_username,
            associated_to="username"
        )
        user.status             =       status
        user.last_seen          =       last_seen
        user.created_at         =       created_at

        # Check if the user owns the account
        if hashed_auth_token == hashed_user_auth_token:
            user.auth_token_expire_time     =       auth_token_expire_time
            user.conversations              =       conversations
            user.contacts                   =       contacts
            user.updated_at                 =       updated_at
            
        user_data = user.to_json()

        # Cleaning up the dict
        element_to_pop = [data for data in user_data if user_data[data] == ""]
    
        for data in element_to_pop:
            user_data.pop(data)
        
        return user_data
    
    def check_user(self, user_id: str, auth_token: str | None=None) -> bool:
        """
        Checks if the user exists or not
        
        Parameters:
            user_id (str): The user's `user_id`
            auth_token (str | None): The user's `auth_token`,
                in case it is None, then we are expecting to 
                check only if the `user_id` exists without
                the match of the raw `auth_token` with this user's `auth_token`

        Returns:
            bool: True is the user exists, otherswise False
        """
        users_id = self.database_handler.get_users_id()

        if user_id not in users_id:
            return False
        
        if auth_token is not None:
            hashed_auth_token = self.auth_token_manager._encrypt_auth_token(
                user_id=user_id,
                auth_token=auth_token
            )
            user_data = self.database_handler.fetch_user_data(user_id=user_id)

            user_auth_token = user_data[7]

            # Check if the `auth_token` don't match
            if hashed_auth_token != user_auth_token:
                return False

        return True
    
    def check_username(self, username: str) -> bool:
        """
        Checks if the `username` already exists or not
        
        Parameters:
            username (str): To check username
        
        Returns:
            bool: True is the username exists, otherwise False
        """
        usernames = self.database_handler.get_usernames()

        if username in usernames:
            return True
        
        return False

    def check_user_password(self, user_id: str, password: str) -> bool:
        """
        Checks if the passed password matches the user's password
        
        Parameters:
            user_id (str): The user's id
            password (str): The user's password
        
        Returns:
            bool: True if the passed password matches the user's password,
            otherwise False it returned
        """
        user_data = self.database_handler.fetch_user_data(
            user_id=user_id
        )
        
        hashed_user_password = base64.b64decode(user_data[2]) # Saved hashed version of the user's password

        hashed_user_passwords_salt = self.database_handler.get_salt(
            user_id=user_id,
            associated_to="password"
        ) # Salt used to encrypt the password

        # Hashed version of the passed password
        hashed_password = self.hasher.encrypt_with_bcrypt(
            data=password,
            salt=hashed_user_passwords_salt,
            is_to_check=True
        )

        if hashed_password != hashed_user_password:
            return False

        return True
    
    def update_username(self, user_id: str, new_username: str) -> None:
        """ 
        Updates the `username`
        
        Parameters:
            user_id (str): The user's `user_id`
            new_username (str): The new username
        """
        user_data = self.database_handler.fetch_user_data(
            user_id=user_id,
        )
        encrypted_old_username = base64.b64decode(user_data[1])

        username_decryption_key = self.database_handler.get_decryption_key(
            user_id=user_id,
            associated_to="username"
        )

        decryption_key = EncryptionKey()

        decryption_key.key_value = username_decryption_key
        decryption_key.user_id = user_id
        decryption_key.associated_to = "username"

        old_username = self.hasher.decrypt_with_blowfish(
            encrypted_data=encrypted_old_username,
            key=username_decryption_key
        )
        
        encrypted_new_username, encryption_key =  self.hasher.encrypt_with_blowfish(data=new_username)

        encrypted_new_username = base64.b64encode(encrypted_new_username).decode("ascii")

        encryption_key.user_id = user_id
        encryption_key.associated_to = "username"

        # Update the username
        self.database_handler.update_username(
            user_id=user_id,
            new_username=encrypted_new_username
        )

        # Update the encryption key info in the database
        self.database_handler.update_encryption_key(
            key=encryption_key
        )

        logger.info(
            constants.UPDATE_USERNAME(
                user_id=user_id,
                old_username=old_username,
                new_username=new_username
            )
        )
    def update_user_status(self, user_id: str, status: str) -> None:
        """
        Updates the user's status
        
        Parameters:
            status (str): Status value. ["online", "offline"]
        """
        user_data = self.database_handler.fetch_user_data(
            user_id=user_id
        )
        users_status = user_data[3]

        if users_status == status:
            logger.info(
                constants.USER_STATUS_UPDATE_SKIPPED(
                    user_id=user_id,
                )
            )
            return

        self.database_handler.update_user_status(
            user_id=user_id,
            status=status
        )

        logger.info(
            constants.UPDATE_USER_STATUS(
                user_id=user_id,
                from_status=users_status,
                to_status=status
            )
        )

    def update_user_password(self, user_id: str, new_password: str, old_password: str) -> None:
        """ 
        Updates the user's password
        
        Parameters:
            user_id (srt): The user's `user_id`
            new_password (srt): The new password to change the old one
            old_password (str): The old password
        """
        salt = self.hasher.encrypt_with_bcrypt(
            data=new_password,
            user_id=user_id
        )
        salt.associated_to = "password"

        hashed_new_password = salt.hashed_data

        self.database_handler.update_user_password(
            user_id=user_id,
            hashed_new_password=hashed_new_password
        )

        self.database_handler.update_salt(
            user_id=user_id,
            associated_to="password",
            new_salt_value=salt.salt_value,
            new_hashed_data=hashed_new_password
        )

        logger.info(
            constants.UPDATE_USER_PASSWORD(
                user_id=user_id,
                hashed_new_password=hashed_new_password
            )
        )

    def _encrypt_data(self, user_id: str, data: str, associated_to: str, algo_type: str) -> str:
        """
        Encrypts the given data
        
        Parameters:
            user_id (str): The user's user_id
            data (str): The data to encrypt
            associated_to (str): What will derived key will be associated to
                [ "username", "auth_token"]

            algo_type (str): Type of algorithm to use to encrypt
        
        Returns:
            str: Encrypted version of the given data
        """
        # For username, messages, contancts data
        if algo_type == "blowfish":
            encrypted_data, encryption_key_data  =  self.hasher.encrypt_with_blowfish(data)

            encrypted_data = base64.b64encode(encrypted_data).decode("ascii")

            encryption_key_data.associated_to   =     associated_to
            encryption_key_data.user_id         =     user_id

            if encryption_key_data.associated_to == "username":
                logger.info(
                    constants.USERNAME_ENCRYPTED(
                        username=data,
                        encrypted_username=encrypted_data
                    )
                )

            self.database_handler.save_encryption_key(
                key=encryption_key_data
            )

            return encrypted_data

        # For passwords, and auth_tokens
        if algo_type == "bcrypt":
            salt = self.hasher.encrypt_with_bcrypt(
                data=data,
                user_id=user_id
            )

            salt.associated_to = associated_to

            if salt.associated_to == "auth_token":
                logger.info(
                    constants.NEW_AUTH_TOKEN_HASHED(
                        auth_token=data,
                        hashed_auth_token=salt.hashed_data,
                        salt=salt
                    )
                )
            elif salt.associated_to == "password":
                logger.info(
                    constants.NEW_PASSWORD_HASHED(
                        password=data,
                        hashed_password=salt.hashed_data
                    )
                )
            
            self.database_handler.save_salt(
                salt=salt
            )

            return salt.hashed_data
    
    def _decrypt_data(self, user_id: str, data: str, associated_to: str) -> str:
        """
        Decrypts the given data

        Parameters:
            user_id (str): The user's user_id
            data (str): The data to decrypt
            associated_to (str): What does derived key associated to
                 [ "username", "auth_token"]
        Returns:
            str: The decrypted data
        """
        decryption_key = self.database_handler.get_decryption_key(
            user_id=user_id,
            associated_to=associated_to
        )
        
        data = base64.b64decode(data)

        decrypted_data = self.hasher.decrypt_with_blowfish(
            data,
            key=decryption_key
        )

        if associated_to == "username":
            logger.info(
                constants.USERNAME_DECRYPTED(
                    encrypted_username=data,
                    decrypted_username=decrypted_data
                )
            )
        
        return decrypted_data

    def _generate_user_id(self) -> str:
        """ Generates a unique user id for a user """
        user_ids = self.database_handler.get_users_id()
        size = 17
        ascii_charachters = [char for char in string.ascii_lowercase + string.ascii_uppercase] 

        for _ in range(10):
            ascii_charachters.append(str(_))
        
        user_id = ""
        
        while True:
            for _ in range(size):
                user_id += random.choice(ascii_charachters)
            
            if user_id not in user_ids:
                break
            else:
                user_id = ""
        
        logger.info(
            constants.NEW_USER_ID_GENERATED(
                user_id=user_id
            )
        )
    
        return user_id
