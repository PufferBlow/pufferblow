import os
import sys
import json
import base64
import datetime
import psycopg2
import psycopg2.pool

from loguru import logger
from rich import print

from pufferblow_api import constants
from pufferblow_api.src.hasher.hasher import Hasher
from pufferblow_api.src.models.salt_model import Salt
from pufferblow_api.src.models.user_model import User
from pufferblow_api.src.models.encryption_key_model import EncryptionKey

class DatabaseHandler (object):
    """ Database handler for PufferBlow's API """
    def __init__(self, database_connection_pool: psycopg2.pool.ThreadedConnectionPool, hasher: Hasher) -> None:
        self.database_connection_pool       =         database_connection_pool
        self.hasher                         =         hasher
    
    def sign_up(self, user_data: User) -> None:
        """ Signs up a new user and returns a auth token """
        database_connection = self.database_connection_pool.getconn()
        try:
            with database_connection.cursor() as cursor:
                add_new_user = "INSERT INTO users (user_id, username, password_hash, status, last_seen, conversations, contacts, auth_token, auth_token_expire_time, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"

                cursor.execute(
                    add_new_user,
                    user_data.to_tuple()
                )
                database_connection.commit()
                
                self.save_auth_token(
                    user_id=user_data.user_id,
                    auth_token=user_data.encrypted_auth_token,
                    auth_token_expire_time=user_data.auth_token_expire_time
                )
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )

    def fetch_user_data(self, user_id: str) -> tuple:
        """ 
            Returns a User model containing
            information about the given user's id
        """
        database_connection = self.database_connection_pool.getconn()
        user_data = None

        try:
            with database_connection.cursor() as cursor:
                sql = "SELECT user_id, username, password_hash, status, last_seen, conversations, contacts, auth_token, auth_token_expire_time, created_at FROM users WHERE user_id = %s"

                cursor.execute(
                    sql,
                    (user_id,)
                )
                user_data = cursor.fetchone()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
        
        return user_data

    def delete_auth_token(self, user_id: str, auth_token: str) -> None:
        """
        Deletes the given encrypted auth_token that belongs to the user_id
        
        Paramters:
            user_id (str): The user's id
            auth_token (str): The raw version of the auth_token to delete
        """ 
        database_connection = self.database_connection_pool.getconn()

        try:
            with database_connection.cursor() as cursor:
                sql = "DELETE * FROM auth_tokens WHERE auth_token = '%s' AND user_id = '%s'"
                cursor.execute(
                    sql,
                    (auth_token, user_id)
                )

                database_connection.commit()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
    
    def save_salt(self, salt: Salt) -> None:
        """ Stores the salt data in the salt table """
        database_connection = self.database_connection_pool.getconn()
        try:
            with database_connection.cursor() as cursor:
                sql = "INSERT INTO salts (salt_value, hashed_data, user_id, associated_to, created_at) VALUES (%s, %s, %s, %s, %s)"
                
                cursor.execute(
                    sql,
                    salt.to_tuple()
                )
                database_connection.commit()

                logger.info(
                    constants.NEW_HASH_SALT_SAVED(
                        salt=salt
                    )
                )
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )

    def save_auth_token(
        self,
        auth_token: bytes,
        auth_token_expire_time: datetime.date.today,
        user_id: str
    ) -> None:
        """ Saves the token to the auth_tokens table """
        database_connection = self.database_connection_pool.getconn()

        try:
            with database_connection.cursor() as cursor:
                sql = "INSERT INTO auth_tokens (auth_token, auth_token_expire_time, user_id) VALUES (%s, %s, %s)"

                cursor.execute(
                    sql,
                    (   
                        auth_token,
                        auth_token_expire_time.strftime("%Y-%m-%d"),
                        user_id
                    ),
                )
                database_connection.commit()

                logger.info(
                    constants.NEW_AUTH_TOKEN_SAVED(
                        auth_token=auth_token
                    )
                )
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )

    def get_users_id(self) -> list:
        """
        Returns a list of all the used users id
        
        Returns:
            list: A list containing all the used `user_id`
        """
        database_connection = self.database_connection_pool.getconn()

        try:
            with database_connection.cursor() as cursor:
                sql = "SELECT user_id FROM users"
                cursor.execute(sql)

                users_id = cursor.fetchall()

                if len(users_id) == 0:
                    users_id = []
                else:
                    users_id = [user_id[0] for user_id in users_id]
                
                logger.info(
                    constants.FETCH_USERS_ID(
                        users_id=users_id
                    )
                )
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )

        return users_id

    def save_encryption_key(self, key: EncryptionKey):
        """ Saves the keys that are used in encryption along side with the salt """
        database_connection = self.database_connection_pool.getconn()
        
        try:
            with database_connection.cursor() as cursor:
                sql = "INSERT INTO keys (key_value, salt, associated_to, user_id, message_id) VALUES (%s, %s, %s, %s, %s)"
                
                cursor.execute(
                    sql,
                    key.to_tuple()
                )
                database_connection.commit()

                logger.info(
                    constants.NEW_DERIVED_KEY_SAVED(
                        key=key
                    )
                )
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
    
    def get_decryption_key(self, associated_to: str, user_id: str| None=None, message_id: str | None=None) -> bytes:
        """ Returns the decryption key from the database """
        database_connection = self.database_connection_pool.getconn()
        key = None

        try:
            with database_connection.cursor() as cursor:
                if user_id is not None:
                    sql = "SELECT key_value FROM keys WHERE user_id = '%s' AND associated_to = '%s'" % (user_id, associated_to)
                else:
                    sql = "SELECT key_value FROM keys WHERE message_id = '%s' AND associated_to = '%s'" % (message_id, associated_to)

                cursor.execute(sql)

                key = cursor.fetchall()[0][0]
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )

        return key

    def get_salt(self, user_id: str, associated_to: str) -> bytes:
        """
        Returns the salt used to hash a password, or auth_token
         
        Parameters:
            user_id (str): The user's id
            associated_to (str): What is the salt associated to
                    ["auth_token", "password"]

        Returns:
            str: salt
        """
        database_connection = self.database_connection_pool.getconn()
        salt = None

        try:
            with database_connection.cursor() as cursor:
                sql = "SELECT salt_value FROM salts WHERE user_id = %s AND associated_to = %s" 

                cursor.execute(
                    sql,
                    (user_id, associated_to)
                )
                salt = cursor.fetchone()[0]
                salt = base64.b64decode(salt)

                logger.info(
                    constants.REQUEST_SALT_VALUE(
                        user_id=user_id,
                        salt_value=salt,
                        associated_to=associated_to
                    )
                )
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
        
        return salt

    def get_auth_token_expire_time(self, user_id: str, auth_token: str) -> str:
        """
        Returns the expire time for the given auth token
        
        Parameters:
            auth_token (str): Encrypted version of the auth token
        
        Returns:
            str: Expire time
        """
        database_connection = self.database_connection_pool.getconn()
        expire_time = None

        try:
            with database_connection.cursor() as cursor:
                sql = "SELECT auth_token_expire_time FROM auth_tokens WHERE user_id = '%s' AND auth_token = '%s'" % (auth_token, user_id)
                cursor.execute(sql)

                expire_time = cursor.fetchone()[0]
        
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
        
        return expire_time
    
    def check_auth_token(self, hashed_auth_token: bytes, user_id: str) -> bool:
        """
        Checks the validity of the `auth_token`
        
        Parameters:
            user_id (str): The user's `user_id`
            hashed_auth_token (bytes): The hash user's `auth_token`
        
        Returns:
            bool: True if the `auth_token` exists, otherwise False
        """
        database_connection = self.database_connection_pool.getconn()
        is_valid = True

        try:
            with database_connection.cursor() as cursor:
                sql = "SELECT * FROM users WHERE user_id = %s AND auth_token = %s"

                cursor.execute(
                    sql,
                    (user_id, hashed_auth_token)
                )

                user_data = cursor.fetchall()

                if len(user_data) != 1:
                    is_valid = False
                
                logger.info(
                    constants.VALIDATE_AUTH_TOKEN(
                        hashed_auth_token=hashed_auth_token,
                        is_valid=is_valid
                    )
                )
                
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
        
        return is_valid
