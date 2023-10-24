import base64
import sqlalchemy

from loguru import logger

from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy import (
    select,
    update,
    delete,
    and_,
    text
)

from pufferblow_api import constants

# Encryption manager
from pufferblow_api.src.hasher.hasher import Hasher

# Models
from pufferblow_api.src.models.salt_model import Salt
from pufferblow_api.src.models.user_model import User
from pufferblow_api.src.models.channel_model import Channel
from pufferblow_api.src.models.encryption_key_model import EncryptionKey

# Utils
from pufferblow_api.src.utils.current_date import date_in_gmt

# Tables
from pufferblow_api.src.database.tables.keys import Keys
from pufferblow_api.src.database.tables.users import Users
from pufferblow_api.src.database.tables.salts import Salts
from pufferblow_api.src.database.tables.channels import Channels
from pufferblow_api.src.database.tables.auth_tokens import AuthTokens

class DatabaseHandler (object):
    """ Database handler for PufferBlow's API """
    def __init__(self, database_engine: sqlalchemy.create_engine, hasher: Hasher) -> None:
        self.database_engine    =    database_engine
        self.database_session   =    sessionmaker(bind=self.database_engine)
        self.hasher             =    hasher
    
    def setup_tables(self, base: DeclarativeBase) -> None:
        """
        Setup the needed database tables
        
        Args:
            `base` (DeclarativeBase): A `DeclarativeBase` sub-class.
        
        Returns:
            `None`.
        """
        # in case a table already exists then it will be skipped
        base.metadata.create_all(self.database_engine)
    
    def sign_up(self, user_data: User) -> None:
        """
        Sign up a new user
        
        Args:
            `user_data` (User): A `User` object.
        
        Returns:
            `None`.
        """
        user_table_metadata = user_data.create_table_metadata()

        with self.database_session() as session:
            session.add(user_table_metadata)

            session.commit()
        
        auth_token = AuthTokens(
            user_id=user_data.user_id,
            auth_token=user_data.encrypted_auth_token,
            auth_token_expire_time=user_data.auth_token_expire_time
        )
        self.save_auth_token(
            auth_token=auth_token
        )

    def fetch_user_data(self, user_id: str) -> Users:
        """ 
        Fetch metadata about the given `user_id`
        from the database

        Args:
            `user_id` (str): The user's `user_id`.
        
        Returns:
            Users: A `Users` table object.
        """
        user: Users = None

        with self.database_session() as session:
            stmt = select(Users).where(
                Users.user_id == user_id
            )

            # NOTE: The returned data is a tuple containing a `Users` table object.
            # To access the `user` object correctly, we specify its position as `0`,
            # ensuring that we can access all the columns without errors.
            # If we don't specify the position, an error will be raised when trying
            # to access the `auth_token` column.

            user = session.execute(stmt).fetchone()[0]

        return user

    def delete_auth_token(self, user_id: str, auth_token: str) -> None:
        """
        Delete the given encrypted `auth_token`
        that belongs to the `user_id`
        
        Args:
            `user_id` (str): The user's `user_id`.
            `auth_token` (str): The encrypted version of the `auth_token` to delete.
        
        Returns:
            `None`.
        """
        with self.database_session() as session:
            stmt = delete(AuthTokens).where(
                and_(
                    AuthTokens.user_id == user_id,
                    AuthTokens.auth_token == auth_token
                )
            )

            session.execute(stmt)
            session.commit()
    
    def save_salt(self, salt: Salt) -> None:
        """
        Save the salt data in the `salt` table
        in the database
        
        Args:
            `salt` (Salt): A `Salt` object.
        
        Returns:
            `None`.
        """
        with self.database_session() as session:
            session.add(salt.create_table_metadata())
            
            session.commit()
        
        logger.info(
            constants.NEW_HASH_SALT_SAVED(
                salt=salt
            )
        )

    def save_auth_token(self, auth_token: AuthTokens) -> None:
        """
        Save the `auth_token` to the `auth_tokens` table
        in the database
        
        Args:
            `auth_token` (str): An `AuthTokens` table object.
            
        Returns:
            `None`.
        """
        hashed_auth_token_value = auth_token.auth_token

        with self.database_session() as session:
            session.add(auth_token)

            session.commit()
        
        logger.info(
            constants.NEW_AUTH_TOKEN_SAVED(
                auth_token=hashed_auth_token_value
            )
        )

    def update_auth_token(self, user_id: str, new_auth_token: str, new_auth_token_expire_time: str) -> None:
        """
        Update the user's `auth_token`
        
        Args:
            `user_id` (str): The user's `user_id`.
            `new_auth_token` (str): The new encrypted generated `auth_token`.
            `new_auth_token_expire_time` (date): The new expire time for the generated `auth_token`.
        
        Returns:
            `None`.
        """
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        with self.database_session() as session:
            stmts = [
                update(AuthTokens).values(
                    auth_token=new_auth_token,
                    auth_token_expire_time=new_auth_token_expire_time,
                    updated_at=updated_at
                ).where(
                    AuthTokens.user_id == user_id
                ),
                update(Users).values(
                    auth_token=new_auth_token,
                    auth_token_expire_time=new_auth_token_expire_time,
                    updated_at=updated_at
                ).where(
                    Users.user_id == user_id
                )
            ]
            for stmt in stmts:
                session.execute(stmt)
            
            session.commit()

        logger.info(
            constants.RESET_USER_AUTH_TOKEN(
                user_id=user_id,
                new_hashed_auth_token=new_auth_token
            )
        )
        
    def get_users_id(self) -> list:
        """
        Fetch a list of all the used `user_id`s
        
        Args:
            `None`.
        
        Returns:
            list: A list containing all the used `user_id`s.
        """
        users_id = None

        with self.database_session() as session:
            stmt = select(Users.user_id)

            reponse = session.execute(stmt).fetchall()
            
            users_id = [user_id[0] for user_id in reponse]
        
        logger.info(
            constants.FETCH_USERS_ID(
                users_id=users_id
            )
        )

        return users_id
    
    def get_usernames(self) -> list[str]:
        """
        Fetch a list of all the `username`s in the database
        
        Args:
            `None`.
        
        Returns:
            list[str]: A list containing all the `username`s in the database.
        """
        usernames = list()

        with self.database_session() as session:
            stmt = select(Users.user_id, Users.username)

            reponse = session.execute(stmt).fetchall()
            
            for i in range(len(reponse)):
                user_id = reponse[i][0]
                encrypted_username = base64.b64decode(reponse[i][1])

                encryption_key = self.get_decryption_key(
                    user_id=user_id,
                    associated_to="username"
                )

                decrypted_username = self.hasher.decrypt_with_blowfish(
                    encrypted_data=encrypted_username,
                    key=encryption_key
                )

                usernames.append(decrypted_username)

        logger.info(
            constants.FETCH_USERNAMES(
                usernames=usernames
            )
        )

        return usernames

    def get_auth_tokens_updated_at(self, user_id: str) -> str:
        """
        Fetch the value of the column `updated_at`
        for the `auth_token`
        
        Args:
            `user_id` (str): The user's `user_id`.
        Returns:
            str: The `updated_at` value in GMT.
        """
        updated_at = None

        with self.database_session() as session:
            stmt = select(AuthTokens.updated_at).where(
                AuthTokens.user_id == user_id
            )

            updated_at = session.execute(stmt).fetchone()[0]
        
        return updated_at

    def update_username(self, user_id: str, new_username: str) -> None:
        """
        Update the `username` for a user 
        
        Args:
            `user_id` (str): The user's `user_id`.
            `new_username` (str): The new `username` for the user.
        
        Returns:
            `None`.
        """
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        with self.database_session() as session:
            stmt = update(Users).values(
                username=new_username,
                updated_at=updated_at
            ).where(
                Users.user_id == user_id
            )

            session.execute(stmt)

            session.commit()

    def update_user_status(self, user_id: str , status: str) -> None:
        """ Updates the user's status 
        
        Args:
            `status` (str): The user's `status` value. ["online", "offline"].
            `last_seen` (str): Last seen time in GMT (in case the status="offline").
        
        Returns:
            `None`.
        """
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        with self.database_session() as session:
            stmts = []

            stmts.append(
                update(Users).values(
                    status=status,
                    updated_at=updated_at
                ).where(
                    Users.user_id == user_id
                )
            )

            if status == "offline":
                stmts.append(
                    update(Users).values(
                        last_seen=date_in_gmt(format="%Y-%m-%d %H:%M:%S")
                    ).where(
                        Users.user_id == user_id
                    )
                )

            for stmt in stmts:
                session.execute(stmt)

            session.commit()
    
    def update_user_password(self, user_id: str, hashed_new_password: str) -> None:
        """Updates the user's password
        
        Args:
            `user_id` (srt): The user's `user_id`.
            `hashed_new_password` (srt): The hashed version of the new `password`.

        Returns:
            `None`.
        """
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        with self.database_session() as session:
            stmt = update(Users).values(
                password_hash=hashed_new_password,
                updated_at=updated_at
            ).where(
                Users.user_id == user_id
            )

            session.execute(stmt)

            session.commit()
        
    def update_encryption_key(self, key: EncryptionKey) -> None:
        """
        Update the given encryption `key` in the database
        
        Args:
            `key` (EncryptionKey): An `EncryptionKey` object.
        
        Returns:
            `None`.
        """
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")
        
        with self.database_session() as session:
            stmt = update(Keys).values(
                key_value=key.key_value,
                associated_to=key.associated_to,
                updated_at=updated_at
            ).where(
                and_(
                    Keys.user_id == key.user_id,
                    Keys.associated_to == key.associated_to
                )
            )

            session.execute(stmt)

            session.commit()

        logger.info(
            constants.DERIVED_KEY_UPDATED(
                key=key
            )
        )
    
    def delete_encryption_key(self, key: EncryptionKey) -> None:
        """
        Delete the given encryption `key` from the database
        
        Args:
            `key` (EncryptionKey): An `EncryptionKey` object.
        
        Returns:
            `None`.
        """
        with self.database_session() as session:
            session.delete(key.create_table_metadata())

            session.commit()
        
        logger.info(
            constants.DERIVED_KEY_DELETED(
                key=key
            )
        )
    
    def save_encryption_key(self, key: EncryptionKey) -> None:
        """
        Save the encryption `key` in the `keys` table
        in the database

        Args:
            `key` (EncryptionKey): An `EncryptionKey` object.
        
        Returns:
            `None`.
        """
        with self.database_session() as session:
            session.add(key.create_table_metadata())

            session.commit()

        logger.info(
            constants.NEW_DERIVED_KEY_SAVED(
                key=key
            )
        )
        
    def get_decryption_key(self, associated_to: str, user_id: str| None=None, message_id: str | None=None) -> str:
        """
        Fetch an decryption `key` from the `keys` table
        in the database
        
        Args:
            `user_id` (str, optional, default: None): The user's `user_id`.
            `associated_to` (str): What data was this `key` used to encrypt.
            `message_id` (str , optional, default: None): The message's `message_id` (In case the encryption `key` was used to encrypt a message).

        Returns:
            str: The encryption `key` value.
        """
        key = None

        with self.database_session() as session:
            stmt = select(
                Keys.key_value
            ).where(
                and_(
                    Keys.user_id == user_id,
                    Keys.associated_to == associated_to
                )
            )

            key = session.execute(stmt).fetchone()[0]
        
        return key

    def get_salt(self, user_id: str, associated_to: str) -> bytes:
        """
        Returns the salt used to hash a `password`,
        or an `auth_token`
        
        Args:
            `user_id` (str): The user's id
            `associated_to` (str): What `data` was this `salt` used to hash ['password'. 'auth_token'].

        Returns:
            bytes: The `salt` value in bytes.
        """
        salt = None

        with self.database_session() as session:
            stmt = select(Salts.salt_value).where(
                and_(
                    Salts.user_id == user_id,
                    Salts.associated_to == associated_to
                )
            )

            salt = session.execute(stmt).fetchone()[0]
            salt = base64.b64decode(salt)

            logger.info(f"{salt = }")
        
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
        Update the `salt` value
        
        Args:
            `user_id` (str): The user's `user_id`.
            `associated_to` (str): What `data` was this `salt` used to hash ['password'. 'auth_token'].
            `new_salt_value` (str): The new `salt` value
            `new_hashed_data` (str): The new hashed `data` with the new `salt` value.
        
        Returns:
            `None`.
        """
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        with self.database_session() as session:
            stmt = update(Salts).values(
                salt_value=new_salt_value,
                hashed_data=new_hashed_data,
                updated_at=updated_at
            ).where(
                and_(
                    Salts.user_id == user_id,
                    Salts.associated_to == associated_to
                )
            )

            session.execute(stmt)
            session.commit()

    def delete_salt(self, user_id: str, associated_to: str) -> None:
        """
        Delete the `salt` from the `salts` table
        in the database
        
        Args:
            `user_id` (str): The user's `user_id`.
            `associated_to` (str): What `data` was this `salt` used to hash ['password'. 'auth_token'].
        
        Returns:
            `None`.
        """
        with self.database_session() as session:
            stmt = delete(Salts).where(
                and_(
                    Salts.user_id == user_id,
                    Salts.associated_to == associated_to
                )
            )

            session.execute(stmt)
            
            session.commit()

    def get_auth_token_expire_time(self, user_id: str, auth_token: str) -> str:
        """
        Fetch the expire time for the given `auth_token`
        from the `auth_token_expire_time` column in the 
        database
        
        Args:
            `auth_token` (str): Encrypted version of the `auth_token`.
        
        Returns:
            str: The `auth_token`'s expire time value.
        """
        expire_time = None

        with self.database_session() as session:
            stmt = select(
                AuthTokens.auth_token_expire_time
            ).where(
                and_(
                    AuthTokens.user_id == user_id,
                    AuthTokens.auth_token == auth_token
                )
            )

            expire_time = session.execute(stmt).fetchone()[0]
        
        return expire_time
    
    def check_auth_token(self, hashed_auth_token: bytes, user_id: str) -> bool:
        """
        Check the validity of the `auth_token`
        
        Args:
            `user_id` (str): The user's `user_id`.
            `hashed_auth_token` (bytes): The hash value of the user's `auth_token`.
        
        Returns:
            bool: True if the `auth_token` exists, otherwise False.
        """
        is_valid = True

        with self.database_session() as session:
            stmt = select(AuthTokens).where(
                and_(
                    AuthTokens.user_id == user_id,
                    AuthTokens.auth_token == hashed_auth_token
                )
            )

            reponse = session.execute(stmt).fetchall()

            if len(reponse) == 0:
                is_valid = not is_valid
        
        logger.info(
            constants.VALIDATE_AUTH_TOKEN(
                hashed_auth_token=hashed_auth_token,
                is_valid=is_valid
            )
        )
        
        return is_valid

    def fetch_channels(self, user_id: str) -> list[tuple[Channels]]:
        """
        Fetch a list of all the available channels, which
        depends on the user. If he is not the server owner
        or an admin then the private channels won't be returned
        
        Args:
            `user_id` (str): The user's `user_id`.
        
        Returns:
            list[tuple[Channels]]: `Channels` table objects.
        """
        channels_metadata = None

        with self.database_session() as session:
            stmt = select(Channels)

            channels_metadata = session.execute(stmt).fetchall()
        
        return channels_metadata

    def get_channels_names(self) -> list[str]:
        """ 
        Fetch a list of `channel_name`s from
        the `channels` table in the database
        
        Args:
            `None`.
        
        Returns:
            list[str]: A list of `channel_name`s.
        """
        channels_names = None

        with self.database_session() as session:
            stmt = select(Channels.channel_name)

            channels_names = session.execute(stmt).fetchall()
        
        return channels_names

    def create_new_channel(self, user_id: str, channel: Channel) -> None:
        """
        Create a new `channel` in the server
        
        Args:
            `user_id` (str): The user's `user_id` (The server owner have the right to create channels).
            `channel` (Channel): A `Channel` object.
        
        Returns:
            `None`.
        """
        with self.database_session() as session:
            session.add(channel.create_table_metadata())

            session.commit()
        
        logger.info(
            constants.NEW_CHANNEL_CREATED(
                user_id=user_id,
                channel_id=channel.channel_id,
                channel_name=channel.channel_name
            )
        )
    
    def get_channel_data(self, channel_id: str) -> Channels:
        """
        Fetch the metadata of a `channel` from
        the `channels` table in the database
        
        Args:
            `channel_id` (str): The channel's `channel_id`.
        
        Returns:
            Channels: A `Channels` table object.
        """
        channel_metadata = None

        with self.database_session() as session:
            stmt = select(
                Channels
            ).where(
                Channels.channel_id == channel_id
            )

            channel_metadata = session.execute(stmt).fetchone()[0]

        return channel_metadata
    
    def delete_channel(self, channel_id: str) -> None:
        """
        Delete a `channel` from the `channels` table
        in the database
        
        Args:
            `channel_id` (str): The channel's `channel_id`.
        
        Returns:
            `None`.
        """
        with self.database_session() as session:
            stmt = delete(Channels).where(
                Channels.channel_id == channel_id
            )

            session.execute(stmt)
            
            session.commit()
    
    def add_user_to_channel(self, to_add_user_id: str, channel_id: str) -> None:
        """
        Add a `user` to a private channel
        
        Args:
            `to_add_user_id` (str): The user's `user_id`.
            `channel_id` (str): The channel's `channel_id`.
        
        Returns:
            `None`.
        """
        with self.database_session() as session:
            stmt = update(Channels).values(
                allowed_users=text("array_append(allowed_users, %s)" % to_add_user_id)
            ).where(
                Channels.channel_id == channel_id
            )

            session.execute(stmt)

            session.commit()

    def remove_user_from_channel(self, to_remove_user_id: str, channel_id: str) -> None:
        """
        Remove a `user` from a private channel
        
        Args:
            `to_remove_user_id` (str): The user's `user_id`.
            `channel_id` (str): The channel's `channel_id`.
        
        Returns:
            `None`.
        """
        with self.database_session() as session:
            stmt = update(Channels).values(
                allowed_users=text("array_remove(allowed_users, %s)" % to_remove_user_id)
            ).where(
                Channels.channel_id == channel_id
            )

            session.execute(stmt)

            session.commit()
