import os
import sys
import json
import base64
import loguru
import psycopg2
import datetime

from pufferblow_api import constants
from pufferblow_api.src.hasher.hasher import Hasher
from pufferblow_api.src.models.user_model import User
from pufferblow_api.src.models.encryption_key_model import EncryptionKey
from pufferblow_api.src.utils.user_id_generator import user_id_generator
from pufferblow_api.src.utils.auth_token_generator import auth_token_generator

class DatabaseHandler (object):
    """ Database handler for PufferBlow's API """
    def __init__(self, database_connenction: psycopg2.connect, hasher: Hasher) -> None:
        self.database_connection =  database_connenction
        self.database_cursor     =  database_connenction.cursor()
        self.hasher              =  hasher
    
    def sign_up(self, user_data: User, is_test_mode: bool | None = False) -> None:
        """ Signs up a new user and returns a auth token """
        auth_token  = auth_token_generator(self._auth_tokens())
        expire_time = datetime.date.today()

        if expire_time.month != 12:
            expire_time = expire_time.replace(
                month=expire_time.month+1
            )
        else:
            expire_time = expire_time.replace(
                month=1,
                year=expire_time.year+1
            )
        
        user_data.auth_token             = auth_token
        user_data.auth_token_expire_time = expire_time

        user_data.created_at = datetime.date.today()
        user_data.last_seen  = datetime.datetime.now()

        encrypted_username, username_encryption_key          =       self.hasher.encrypt(user_data.username)
        encrypted_auth_token, auth_token_encryption_key      =       self.hasher.encrypt(user_data.auth_token)
        encrypted_email, email_encryption_key                =       self.hasher.encrypt(user_data.email)

        username_encryption_key.associated_to, username_encryption_key.user_id =  \
            constants.ASSOCIATIONS["user_id"][0], \
                user_data.user_id
        auth_token_encryption_key.associated_to, auth_token_encryption_key.user_id = \
            constants.ASSOCIATIONS["user_id"][1], \
                user_data.user_id
        email_encryption_key.associated_to, email_encryption_key.user_id =  \
            constants.ASSOCIATIONS["user_id"][2], \
                user_data.user_id
        
        encryption_keys_data = [
            username_encryption_key,
            auth_token_encryption_key,
            email_encryption_key
        ]

        for encryption_key_data in encryption_keys_data:
            self._save_keys(encryption_key_data)
        
        user_data.username      =      base64.b64encode(encrypted_username).decode("ascii")
        user_data.auth_token    =      base64.b64encode(encrypted_auth_token).decode("ascii")
        user_data.email         =      base64.b64encode(encrypted_email).decode("ascii")

        add_new_user = "INSERT INTO users (user_id, username, email, password_hash, status, last_seen, conversations, contacts, auth_token, auth_token_expire_time, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"

        self.database_cursor.execute(add_new_user, user_data.to_tuple())
        self.database_connection.commit()

        self._save_token(
            user_data.auth_token,
            user_data.auth_token_expire_time,
            user_data.user_id
        )

        return (user_data.auth_token, user_data.auth_token_expire_time) \
                if is_test_mode != True \
                    else (user_data.auth_token, user_data.auth_token_expire_time, user_data.user_id)

    def _save_token(
        self,
        auth_token: bytes,
        auth_token_expire_time: datetime.date.today,
        user_id: str
    ) -> None:
        """ Saves the token to the auth_tokens table """
        sql = "INSERT INTO auth_tokens (auth_token, auth_token_expire_time, user_id) VALUES (%s, %s, %s)"
        
        self.database_cursor.execute(
            sql,
            (   
                auth_token,
                auth_token_expire_time.strftime("%Y-%m-%d"),
                user_id
            ),
        )
        self.database_connection.commit()

    def _auth_tokens(self) -> list:
        """ Returns all the auth tokens that are still haven't expired """
        auth_tokens = []
        
        sql = "SELECT user_id, auth_token FROM auth_tokens"
        self.database_cursor.execute(sql)

        users_data = self.database_cursor.fetchall()

        if len(users_data) == 0:
            return auth_tokens

        for user_data in users_data:
            user_id                 =   user_data[0]
            encrypted_auth_token    =   base64.b64decode(user_data[1])
            get_decryption_key_sql  =   "SELECT key_value FROM keys WHERE user_id = '%s' AND associated_to = 'auth_token'" % user_id
            
            self.database_cursor.execute(get_decryption_key_sql)

            decryption_key = self.database_cursor.fetchall()[0][0]

            auth_token = self.hasher.decrypt(encrypted_auth_token, decryption_key)

            auth_tokens.append(auth_token)

        return auth_tokens

    def _users_id(self) -> list:
        """ Returns a list of all the used users id """
        sql = "SELECT user_id FROM users"
        self.database_cursor.execute(sql)

        user_ids = self.database_cursor.fetchall()

        if len(user_ids) == 0:
            user_ids = []
        else:
            user_ids = [user_id[0] for user_id in user_ids]

        return user_ids

    def _save_keys(self, keys: EncryptionKey):
        """ Saves the keys that are used in encryption along side with the salt """
        sql = "INSERT INTO keys (key_value, salt, associated_to, user_id, message_id) VALUES (%s, %s, %s, %s, %s)"
        
        self.database_cursor.execute(sql, keys.to_tuple())
        self.database_connection.commit()
