import base64
import psycopg2
import psycopg2.pool

from loguru import logger

from pufferblow_api import constants
from pufferblow_api.src.hasher.hasher import Hasher
from pufferblow_api.src.models.salt_model import Salt
from pufferblow_api.src.models.user_model import User
from pufferblow_api.src.models.channel_model import Channel
from pufferblow_api.src.models.encryption_key_model import EncryptionKey

from pufferblow_api.src.utils.current_date import date_in_gmt

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
                add_new_user = "INSERT INTO users (user_id, username, password_hash, status, last_seen, conversations, contacts, auth_token, auth_token_expire_time, created_at, updated_at, is_admin, is_owner) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"

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
                sql = "SELECT user_id, username, password_hash, status, last_seen, conversations, contacts, auth_token, auth_token_expire_time, created_at, updated_at, is_admin, is_owner FROM users WHERE user_id = %s"

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
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
        
        logger.info(
            constants.NEW_HASH_SALT_SAVED(
                salt=salt
            )
        )

    def save_auth_token(
        self,
        auth_token: str,
        auth_token_expire_time: str,
        user_id: str
    ) -> None:
        """ Saves the token to the auth_tokens table """
        database_connection = self.database_connection_pool.getconn()

        try:
            with database_connection.cursor() as cursor:
                sql = "INSERT INTO auth_tokens (auth_token, auth_token_expire_time, user_id, updated_at) VALUES (%s, %s, %s, %s)"

                cursor.execute(
                    sql,
                    (   
                        auth_token,
                        auth_token_expire_time,
                        user_id,
                        None
                    ),
                )
                database_connection.commit()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
        
        logger.info(
            constants.NEW_AUTH_TOKEN_SAVED(
                auth_token=auth_token
            )
        )
        

    def update_auth_token(self, user_id: str, new_auth_token: str, new_auth_token_expire_time: str) -> None:
        """
        Updates the user's auth_token
        
        Parameters:
            user_id (str): The user's id
            new_auth_token (str): The new hashed generated `auth_token`
            new_auth_token_expire_time (date): The new expire time for the generated `auth_token`
        """
        database_connection = self.database_connection_pool.getconn()
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        try:
            with database_connection.cursor() as cursor:
                update_auth_tokens_table_sql = "UPDATE auth_tokens SET auth_token = %s, auth_token_expire_time = %s, updated_at = %s WHERE user_id = %s"
                update_users_table_sql = "UPDATE users SET auth_token = %s, updated_at = %s WHERE user_id = %s"

                sql = """
                    {update_auth_tokens_table_sql};
                    {update_users_table_sql};
                """.format(
                    update_auth_tokens_table_sql=update_auth_tokens_table_sql,
                    update_users_table_sql=update_users_table_sql
                )
                
                cursor.execute(
                    sql,
                    (
                        new_auth_token,
                        new_auth_token_expire_time,
                        updated_at,
                        user_id,
                        new_auth_token,
                        updated_at,
                        user_id
                    )
                )
                database_connection.commit()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )

        logger.info(
            constants.RESET_USER_AUTH_TOKEN(
                user_id=user_id,
                new_hashed_auth_token=new_auth_token
            )
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
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )

        logger.info(
            constants.FETCH_USERS_ID(
                users_id=users_id
            )
        )
        
        return users_id
    
    def get_usernames(self) -> list[str]:
        """ Returns a list of all the usernames in the database """
        database_connection = self.database_connection_pool.getconn()
        usernames = []

        try:
            with database_connection.cursor() as cursor:
                sql = "SELECT user_id, username FROM users"

                cursor.execute(sql)

                users_data = cursor.fetchall()

                for user_data in users_data:
                    user_id, username = user_data

                    username = base64.b64decode(username)

                    decryption_key = self.get_decryption_key(
                        user_id=user_id,
                        associated_to="username"
                    )

                    username = self.hasher.decrypt_with_blowfish(
                        encrypted_data=username,
                        key=decryption_key
                    )

                    usernames.append(username)
        finally:
            self.database_connection_pool.putconn(
                database_connection, 
                close=False
            )
        
        logger.info(
            constants.FETCH_USERNAMES(
                usernames=usernames
            )
        )

        return usernames

    def get_auth_tokens_updated_at(self, user_id: str) -> str:
        """
        Returns the value in the column `updated_at`
        for the auth_token
        
        Parameters:
            user_id (str): The user's id
        Returns:
            str: The `updated_at` value in GMT
        """
        database_connection = self.database_connection_pool.getconn()
        updated_at = None

        try:
            with database_connection.cursor() as cursor:
                sql = "SELECT updated_at FROM auth_tokens WHERE user_id = %s"

                cursor.execute(
                    sql, 
                    (user_id, )
                )
                updated_at = cursor.fetchone()[0]
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
        
        return updated_at

    def update_username(self, user_id:str, new_username: str) -> None:
        """ Updates the username 
        
        Parameters:
            user_id (str): The user's `user_id`
            new_username (str): The new username
        """
        database_connection = self.database_connection_pool.getconn()
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        try:
            with database_connection.cursor() as cursor:
                sql = "UPDATE users SET username = %s, updated_at = %s WHERE user_id = %s"

                cursor.execute(
                    sql,
                    (
                        new_username,
                        updated_at,
                        user_id
                    )
                )
                database_connection.commit()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )

    def update_user_status(self, user_id: str ,status: str):
        """ Updates the user's status 
        
        Parameters:
            status (str): Status value. ["online", "offline"]
            last_seen (str): Last seen time in GMT (in case the status="offline")
        """
        database_connection = self.database_connection_pool.getconn()
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        try:
            with database_connection.cursor() as cursor:
                sql = None
                changes = None

                if status == "offline":
                    last_seen = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

                    sql = "UPDATE users SET status = %s, last_seen = %s, updated_at = %s WHERE user_id = %s"
                    changes = (status, last_seen, updated_at, user_id)
                else:
                    sql = "UPDATE users SET status = %s, updated_at = %s WHERE user_id = %s"
                    changes = (status, updated_at, user_id)
                
                cursor.execute(
                    sql,
                    changes
                )
                database_connection.commit()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
    
    def update_user_password(self, user_id: str, hashed_new_password: str) -> None:
        """Updates the user's password
        
        Parameters:
            user_id (srt): The user's `user_id`
            hashed_new_password (srt): The hash of the new password to change the old one
        """
        database_connection = self.database_connection_pool.getconn()
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        try:
            with database_connection.cursor() as cursor:
                sql = "UPDATE users SET password_hash = %s, updated_at = %s WHERE user_id = %s"

                cursor.execute(
                    sql,
                    (
                        hashed_new_password,
                        updated_at,
                        user_id
                    )
                )
                database_connection.commit()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
    
    def update_encryption_key(self, key: EncryptionKey) -> None:
        """ Updates the given encryption key """
        database_connection = self.database_connection_pool.getconn()
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        try:
            with database_connection.cursor() as cursor:
                sql = "UPDATE keys SET key_value = %s, updated_at = %s WHERE user_id = %s AND associated_to = %s"

                cursor.execute(
                    sql,
                    (key.key_value, updated_at, key.user_id, key.associated_to)
                )
                database_connection.commit()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
        
        logger.info(
            constants.DERIVED_KEY_UPDATED(
                key=key
            )
        )
    
    def delete_encryption_key(self, key: EncryptionKey) -> None:
        """ Deletes the given encryption key """
        database_connection = self.database_connection_pool.getconn()

        try:
            with database_connection.cursor() as cursor:
                sql = "DELETE FROM keys WHERE user_id = %s AND key_value = %s AND associated_to = %s"

                cursor.execute(
                    sql,
                    (key.user_id, key.key_value, key.associated_to)
                )
                database_connection.commit()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
        
        logger.info(
            constants.DERIVED_KEY_DELETED(
                key=key
            )
        )
    
    def save_encryption_key(self, key: EncryptionKey):
        """ Saves the keys that are used in encryption along side with the salt """
        database_connection = self.database_connection_pool.getconn()
        
        try:
            with database_connection.cursor() as cursor:
                sql = "INSERT INTO keys (key_value, associated_to, user_id, message_id, created_at) VALUES (%s, %s, %s, %s, %s)"
                
                cursor.execute(
                    sql,
                    key.to_tuple()
                )
                database_connection.commit()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )

        logger.info(
            constants.NEW_DERIVED_KEY_SAVED(
                key=key
            )
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
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
        
        logger.info(
            constants.REQUEST_SALT_VALUE(
                user_id=user_id,
                salt_value=salt,
                associated_to=associated_to
            )
        )

        return salt

    def update_salt(self, user_id: str, associated_to: str, new_salt_value: str, new_hashed_data: str) -> None:
        """ 
        Updates the salt value
        
        Parameters:
            user_id (str): The user's id
            associated_to (str): password, auth_token
            new_salt_value (str): The new salt value
        """
        database_connection = self.database_connection_pool.getconn()
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")
        
        try:
            with database_connection.cursor() as cursor:
                sql = "UPDATE salts SET salt_value = %s, hashed_data = %s, updated_at = %s WHERE user_id = %s AND associated_to = %s"

                cursor.execute(
                    sql,
                    (   
                        new_salt_value,
                        new_hashed_data,
                        updated_at,
                        user_id,
                        associated_to
                    )
                )
                database_connection.commit()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )

    def delete_salt(self, user_id: str, associated_to: str) -> None:
        """ Deletes the salt data from the salts table """
        database_connection = self.database_connection_pool.getconn()

        try:
            with database_connection.cursor() as cursor:
                sql = "DELETE FROM salts WHERE user_id = %s AND associated_to = %s"

                cursor.execute(
                    sql,
                    (
                        user_id,
                        associated_to
                    )
                )
                database_connection.commit()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )

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
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
        
        logger.info(
            constants.VALIDATE_AUTH_TOKEN(
                hashed_auth_token=hashed_auth_token,
                is_valid=is_valid
                )
            )
        
        return is_valid

    def fetch_channels(self, user_id: str) -> list:
        """ Returns a list of all the available channels """
        database_connection = self.database_connection_pool.getconn()
        channels_data = None

        try:
            with database_connection.cursor() as cursor:
                sql = """
                    SELECT channel_id, channel_name, messages_ids, is_private, allowed_users, created_at
                    FROM channels
                    WHERE NOT is_private OR (is_private AND %s = ANY(allowed_users));
                """
                
                cursor.execute(
                    sql,
                    (user_id, )
                )
                
                channels_data = cursor.fetchall()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
        
        return channels_data

    def get_channels_names(self) -> list[str]:
        """ Returns a list of channel_name """
        database_connection = self.database_connection_pool.getconn()
        channels_names = None

        try:
            with database_connection.cursor() as cursor:
                sql = "SELECT channel_name FROM channels"

                cursor.execute(sql)
                channels_names = [channel_id[0] for channel_id in cursor.fetchall()]
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
        
        return channels_names

    def create_new_channel(self, user_id: str, channel: Channel) -> None:
        """ Registers a new channel into the channels table """
        database_connection = self.database_connection_pool.getconn()

        try:
            with database_connection.cursor() as cursor:
                sql = "INSERT INTO channels (channel_id, channel_name, messages_ids, is_private, allowed_users, created_at) VALUES (%s, %s, %s, %s, %s, %s)"

                cursor.execute(
                    sql,
                    channel.to_tuple()
                )
                database_connection.commit()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )

        logger.info(
            constants.NEW_CHANNEL_CREATED(
                user_id=user_id,
                channel_id=channel.channel_id,
                channel_name=channel.channel_name
            )
        )
    
    def get_channel_data(self, user_id:str, channel_id: str) -> None:
        """ Returns the data of a channel based off it\s channel_id """
        database_connection = self.database_connection_pool.getconn()
        channel_data = None

        try:
            with database_connection.cursor() as cursor:
                sql = "SELECT channel_id, channel_name, messages_ids, is_private, allowed_users, created_at FROM channels WHERE channel_id = %s"

                cursor.execute(
                    sql,
                    (channel_id,)
                )
                channel_data = cursor.fetchone()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
        
        logger.info(
            constants.REQUESTED_CHANNEL_DATA(
                viewer_user_id=user_id,
                channel_id=channel_id
            )
        )

        return channel_data
    
    def delete_channel(self, channel_id: str) -> None:
        """ Deletes a channel from the channels table based off it's `channel_id` """
        database_connection = self.database_connection_pool.getconn()

        try:
            with database_connection.cursor() as cursor:
                sql = "DELETE FROM channels WHERE channel_id = %s"

                cursor.execute(
                    sql,
                    (channel_id, )
                )
                database_connection.commit()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
    
    def add_user_to_channel(self, to_add_user_id: str, channel_id: str) -> None:
        """ Addes a user to a private channel """
        database_connection = self.database_connection_pool.getconn()

        try:
            with database_connection.cursor() as cursor:
                sql = "UPDATE channels SET allowed_users = array_append(allowed_users, %s) WHERE channel_id = %s"

                cursor.execute(
                    sql,
                    (to_add_user_id, channel_id)
                )
                database_connection.commit()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )

    def remove_user_from_channel(self, to_remove_user_id: str, channel_id: str) -> None:
        """ Removes a user from a private channel """
        database_connection = self.database_connection_pool.getconn()

        try:
            with database_connection.cursor() as cursor:
                sql = "UPDATE channels SET allowed_users = array_remove(allowed_users, %s) WHERE channel_id = %s"

                cursor.execute(
                    sql,
                    (to_remove_user_id, channel_id)
                )
                database_connection.commit()
        finally:
            self.database_connection_pool.putconn(
                database_connection,
                close=False
            )
