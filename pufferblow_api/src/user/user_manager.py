import os
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

class UserManager (object):
    """ User manager class """
    def __init__(self, database_handler: DatabaseHandler, auth_token_manager: AuthTokenManager,hasher: Hasher) -> None:
        self.database_handler   =     database_handler
        self.auth_token_manager =     auth_token_manager
        self.hasher             =     hasher
    
    def sign_up(self, username: str, email: str, password: str) -> User:
        """ 
        Signs up a new user
        
        Parameters:
            username (str): The user's username
            email    (str): The user's email
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
        new_user.email                                  =       self._encrypt_data(
            user_id=new_user.user_id,
            data=email,
            associated_to="email",
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
        new_user.status                                 =       "ONLINE"
        new_user.contacts                               =       []
        new_user.conversations                          =       []
        new_user.created_at                             =       datetime.date.today()
        new_user.last_seen                              =       datetime.datetime.now()

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
        encrypted_email                 =       user_data[2]
        hashed_user_auth_token          =       user_data[8]
        auth_token_expire_time          =       user_data[9]

        status      =   user_data[4]
        last_seen   =   user_data[5]
        created_at  =   user_data[10]
        
        conversations   =   user_data[6]
        contacts        =   user_data[7]

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
            user.email                      =  self._decrypt_data( \
                user_id=user_id,\
                    data=encrypted_email, \
                        associated_to="email" \
                            )
            user.auth_token_expire_time     =       auth_token_expire_time
            user.conversations              =       conversations
            user.contacts                   =       contacts
        
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

            user_auth_token = user_data[8]

            # Check if the `auth_token` don't match
            if hashed_auth_token != user_auth_token:
                return False

        return True

    def _encrypt_data(self, user_id: str, data: str, associated_to: str, algo_type: str) -> str:
        """
        Encrypts the given data
        
        Parameters:
            user_id (str): The user's user_id
            data (str): The data to encrypt
            associated_to (str): What will derived key will be associated to
                [ "username", "email", "auth_token"]

            algo_type (str): Type of algorithm to use to encrypt
        
        Returns:
            str: Encrypted version of the given data
        """
        # For username, email, messages, contancts data
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
            elif encryption_key_data.associated_to == "email":
                logger.info(
                    constants.EMAIL_ENCRYPTED(
                        email=data,
                        encrypted_email=encrypted_data
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
                 [ "username", "email", "auth_token"]
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
        elif associated_to == "email":
            logger.info(
                constants.EMAIL_DECRYPTED(
                    encrypted_email=data,
                    decrypted_email=decrypted_data
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
