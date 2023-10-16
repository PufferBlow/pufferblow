import random
import string
import base64
import datetime

from loguru import logger

from pufferblow_api import constants
from pufferblow_api.src.hasher.hasher import Hasher
from pufferblow_api.src.database.database_handler import DatabaseHandler

class AuthTokenManager (object):
    """ Auth token class to manage auth tokens """
    def __init__(self, database_handler: DatabaseHandler, hasher: Hasher) -> None:
        self.database_handler =     database_handler
        self.hasher           =     hasher
    
    def token_exists(self, user_id: str, hashed_auth_token: str):
        """
        Check if the `auth_token` exists.

        Args:
            `user_id` (str): The user's `user_id`.
            `hashed_auth_token` (str): The hashed user's `auth_token`.
        
        Returns:
            bool: True if the `auth_token` exists, False otherwise.
        """
        return self.database_handler.check_auth_token(
            user_id=user_id,
            hashed_auth_token=hashed_auth_token
        )

    def check_auth_token_format(self, auth_token: str) -> bool:
        """
        Check the `auth_token` format 
        
        Args:
            `auth_token` (str): The raw auth_token.
        
        Returns:
            bool: False if the format of the auth_token is bad otherwise True.
        """
        # NOTE: auth_token is formed from the user_id and the auth_token itself
        # example: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.uSrBsausJJJwYsvBHfi145RYSEorgQjIfuWtpZTjc"
        # the first half of the auth_token is the user_id and it length will always be 36 chars
        # as for the second half wich the actual auth_token it's length is 41
        if "." not in auth_token:
            return False

        user_id = auth_token.split(".")[0]
        auth_token = auth_token.split(".")[1]

        if len(user_id) != 36 or len(auth_token) != 41:
            return False
        
        return True
    
    def is_token_valid(self, user_id: str, auth_token: str) -> bool:
        """
        Check if the `auth_token` is valid and not expired.

        Args:
            `user_id` (str): The user's `user_id`.
            `auth_token` (str): The encrypted version of the `auth_token`.

        Returns:
        bool: True if the token is valid, False otherwise.
        """
        result = None

        expire_time = self.database_handler.get_auth_token_expire_time(
            user_id=user_id,
            auth_token=auth_token
        )

        month = int(expire_time.split("-")[1])
        year  = int(expire_time.split("-")[0])

        current_month = datetime.date.today().month
        current_year  = datetime.date.today().year

        # Check if the month is greater then the current month
        # if so, the False will be returned, and this is because
        # the limit of each auth token is one month.and if not then
        #  we check the year.
        if month > current_month:
            result = False
        else:
            if year > current_year:
                result = False
            result = True
        
        return result

    def create_token(self) -> str:
        """
        Generate a unique `auth_token` for a user
        
        Returns:
            str: The raw auth token.
        """
        size = 41
        ascii_charachters = [char for char in string.ascii_lowercase + string.ascii_uppercase] 

        for _ in range(10):
            ascii_charachters.append(str(_))
        
        auth_token = ""
        
        while True:
            for _ in range(size):
                auth_token += random.choice(ascii_charachters)

            break
        
        logger.info(
            constants.NEW_AUTH_TOKEN_GENERATED(
                auth_token=auth_token
            )
        )
        return auth_token

    def delete_token(self, user_id: str, auth_token: str) -> None:
        """
        Delete an `auth_token` from the database.
        
        Paramters:
            `user_id` (str): The user's `user_id`.
            `auth_token` (str): The raw version of the `auth_token` to delete.
        
        Returns:
            `None`.
        """
        hashed_auth_token = self._encrypt_auth_token(
            user_id=user_id,
            auth_token=auth_token
        )

        self.database_handler.delete_auth_token(
            user_id=user_id,
            auth_token=hashed_auth_token
        )
    
    def auth_token_expire_time(self):
        """ Returns the expire time for `auth_token` """
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
        
        return expire_time.strftime("%Y-%m-%d")
    
    def _encrypt_auth_token(self, user_id: str, auth_token: str) -> str:
        """ 
        Returns the hashed version of the auth_token using the same salt that
        is soted in the database
        
        Args:
            `user_id` (str): The user's `user_id`.
            `auth_token` (str): The raw `auth_token` that is given to the user when signing up.
        
        Returns:
            str: hashed version of the `auth_token``
        """
        salt = self.database_handler.get_salt(
            user_id=user_id,
            associated_to="auth_token"
        )

        auth_token_hash = self.hasher.encrypt_with_bcrypt(
            data=auth_token,
            salt=salt,
            is_to_check=True
        )
        auth_token_hash = base64.b64encode(auth_token_hash).decode("ascii")
        
        return auth_token_hash
