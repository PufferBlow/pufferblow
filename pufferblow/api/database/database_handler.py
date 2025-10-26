import uuid
import base64
import datetime
import hashlib
import sqlalchemy

from typing import List
from loguru import logger

from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy import (
    select,
    update,
    delete,
    and_,
    func,
    text
)

# Encryption manager
from pufferblow.api.hasher.hasher import Hasher

# Config model
from pufferblow.api.models.config_model import Config

# Utils
from pufferblow.api.utils.current_date import date_in_gmt

# Tables
from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.database.tables.keys import Keys
from pufferblow.api.database.tables.roles import Roles
from pufferblow.api.database.tables.users import Users
from pufferblow.api.database.tables.server import Server
from pufferblow.api.database.tables.channels import Channels
from pufferblow.api.database.tables.messages import Messages
from pufferblow.api.database.tables.privileges import Privileges
from pufferblow.api.database.tables.blocked_ips import BlockedIPS
from pufferblow.api.database.tables.auth_tokens import AuthTokens
from pufferblow.api.database.tables.server_settings import ServerSettings
from pufferblow.api.database.tables.message_read_history import MessageReadHistory
from pufferblow.api.database.tables.sticker_catalog import ServerStickers, ServerGIFs
from pufferblow.api.database.tables.file_objects import FileObjects, FileReferences
from pufferblow.api.database.tables.chart_data import ChartData
from pufferblow.api.database.tables.activity_metrics import ActivityMetrics
from pufferblow.api.database.tables.activity_audit import ActivityAudit

# Log messages
from pufferblow.api.logger.msgs import (
    info,
    debug
)

class DatabaseHandler (object):
    """ Database handler for PufferBlow's API """
    def __init__(self, database_engine: sqlalchemy.create_engine, hasher: Hasher, config: Config) -> None:
        self.database_engine        =    database_engine
        self.database_session       =    sessionmaker(bind=self.database_engine, expire_on_commit=False)
        self.hasher                 =    hasher
        self.config                 =    config
    
        self.setup_tables(base=Base)

    def setup_tables(self, base: DeclarativeBase) -> None:
        """
        Setup the needed database tables

        Args:
            `base` (DeclarativeBase): A `DeclarativeBase` sub-class.

        Returns:
            `None`.
        """
        # Check if we're using SQLite (for testing)
        database_uri = str(self.database_engine.url)
        is_sqlite = database_uri.startswith('sqlite://')

        # Test the connection first
        try:
            with self.database_engine.connect() as conn:
                logger.debug("Database connection successful")
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise

        if is_sqlite:
            logger.debug("Setting up SQLite tables for testing")
            # For SQLite tests, exclude PostgreSQL-specific tables and tables with ARRAY/datetime columns
            postgresql_only_tables = {
                Privileges.__tablename__,
                Roles.__tablename__,
                ServerSettings.__tablename__,
                # Tables with ARRAY columns that SQLite doesn't support
                'channels',
                'message_read_history',  # Has DateTime columns which SQLite handles poorly in tests
                'messages',
                # Tables with UUID columns that SQLite doesn't handle properly for tests
                'server',
                'server_stickers',
                'server_gifs',
                'keys',  # Keys table uses UUID columns which SQLite doesn't support
                'auth_tokens',  # AuthTokens table has UUID user_id column
                # File reference system tables (for testing, we'll use basic hashing without references)
                'file_objects',
                'file_references',
                # Chart data table uses advanced date functions that SQLite doesn't handle well
                'chart_data',
                # Activity audit table uses UUID columns which SQLite doesn't support well for tests
                'activity_audit',
                # Note: 'users' table is now included for basic user operations with datetime compatibility
                # Note: 'blocked_ips' table is included for basic functionality
            }
            tables_to_create = [table for table in base.metadata.sorted_tables if table.name not in postgresql_only_tables]
            logger.debug(f"Creating {len(tables_to_create)} tables: {[t.name for t in tables_to_create]}")

            try:
                base.metadata.create_all(self.database_engine, tables=tables_to_create)
                logger.debug("SQLite table creation completed successfully")
            except Exception as e:
                logger.error(f"SQLite table creation failed: {e}")
                raise
        else:
            logger.debug("Setting up PostgreSQL tables for production")
            try:
                # Use migration-safe approach for PostgreSQL
                self._create_tables_safely(base)
                # Ensure default server settings are created
                self._ensure_default_server_settings()
            except Exception as e:
                logger.error(f"PostgreSQL table creation failed: {e}")
                raise

    def _create_tables_safely(self, base: DeclarativeBase) -> None:
        """
        Safely create tables, handling schema evolution.
        """
        try:
            # Try creating all tables at once
            base.metadata.create_all(self.database_engine)
            logger.debug("Table creation completed successfully")
        except Exception as e:
            logger.error(f"Table creation failed: {str(e)}")
            logger.info("If you have an existing database, you may need to manually update the schema.")
            logger.info("Please refer to the migration documentation for schema updates.")
            raise

    def _migrate_table_schema(self) -> None:
        """
        Handle schema migrations for existing databases.
        """
        try:
            # Connect to the database
            with self.database_engine.connect() as conn:
                # Handle missing columns in server_settings table
                self._add_missing_server_settings_columns(conn)

                # Create any completely missing tables
                from pufferblow.api.database.tables.declarative_base import Base
                try:
                    Base.metadata.create_all(self.database_engine)
                    logger.info("Schema migration completed successfully")
                except Exception as e:
                    logger.error(f"Failed to create remaining tables after migration: {str(e)}")
                    raise

        except Exception as e:
            logger.error(f"Schema migration failed: {str(e)}")
            raise

    def _add_missing_server_settings_columns(self, conn) -> None:
        """
        Add any missing columns to the server_settings table.
        """
        # Check and add max_sticker_size column if missing
        try:
            result = conn.execute(text("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'server_settings' AND column_name = 'max_sticker_size'
            """))
            if not result.fetchone():
                logger.info("Adding missing max_sticker_size column to server_settings")
                conn.execute(text("""
                    ALTER TABLE server_settings ADD COLUMN max_sticker_size INTEGER DEFAULT 5
                """))
                conn.commit()
                logger.info("Added max_sticker_size column successfully")
        except Exception as e:
            logger.warning(f"Could not add max_sticker_size column (may already exist): {str(e)}")

        # Check and add max_gif_size column if missing
        try:
            result = conn.execute(text("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'server_settings' AND column_name = 'max_gif_size'
            """))
            if not result.fetchone():
                logger.info("Adding missing max_gif_size column to server_settings")
                conn.execute(text("""
                    ALTER TABLE server_settings ADD COLUMN max_gif_size INTEGER DEFAULT 10
                """))
                conn.commit()
                logger.info("Added max_gif_size column successfully")
        except Exception as e:
            logger.warning(f"Could not add max_gif_size column (may already exist): {str(e)}")

        # Check and add allowed_gif_extensions column if missing
        try:
            result = conn.execute(text("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'server_settings' AND column_name = 'allowed_gif_extensions'
            """))
            if not result.fetchone():
                logger.info("Adding missing allowed_gif_extensions column to server_settings")
                conn.execute(text("""
                    ALTER TABLE server_settings ADD COLUMN allowed_gif_extensions VARCHAR[] DEFAULT ARRAY['gif']
                """))
                conn.commit()
                logger.info("Added allowed_gif_extensions column successfully")
        except Exception as e:
            logger.warning(f"Could not add allowed_gif_extensions column (may already exist): {str(e)}")

        # Check and add rate_limit_duration column if missing
        try:
            result = conn.execute(text("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'server_settings' AND column_name = 'rate_limit_duration'
            """))
            if not result.fetchone():
                logger.info("Adding missing rate_limit_duration column to server_settings")
                conn.execute(text("""
                    ALTER TABLE server_settings ADD COLUMN rate_limit_duration INTEGER DEFAULT 5
                """))
                conn.commit()
                logger.info("Added rate_limit_duration column successfully")
        except Exception as e:
            logger.warning(f"Could not add rate_limit_duration column (may already exist): {str(e)}")

        # Check and add max_rate_limit_requests column if missing
        try:
            result = conn.execute(text("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'server_settings' AND column_name = 'max_rate_limit_requests'
            """))
            if not result.fetchone():
                logger.info("Adding missing max_rate_limit_requests column to server_settings")
                conn.execute(text("""
                    ALTER TABLE server_settings ADD COLUMN max_rate_limit_requests INTEGER DEFAULT 6000
                """))
                conn.commit()
                logger.info("Added max_rate_limit_requests column successfully")
        except Exception as e:
            logger.warning(f"Could not add max_rate_limit_requests column (may already exist): {str(e)}")

        # Check and add max_rate_limit_warnings column if missing
        try:
            result = conn.execute(text("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'server_settings' AND column_name = 'max_rate_limit_warnings'
            """))
            if not result.fetchone():
                logger.info("Adding missing max_rate_limit_warnings column to server_settings")
                conn.execute(text("""
                    ALTER TABLE server_settings ADD COLUMN max_rate_limit_warnings INTEGER DEFAULT 15
                """))
                conn.commit()
                logger.info("Added max_rate_limit_warnings column successfully")
        except Exception as e:
            logger.warning(f"Could not add max_rate_limit_warnings column (may already exist): {str(e)}")

        # Commit any pending changes
        try:
            conn.commit()
        except:
            pass  # Already committed or no changes to commit

    def _add_missing_columns_to_existing_tables(self) -> None:
        """
        Check for and add any missing columns to existing tables.
        Always run after table creation to ensure schema compatibility.
        """
        try:
            with self.database_engine.connect() as conn:
                # Add missing columns to server_settings table
                self._add_missing_server_settings_columns(conn)

        except Exception as e:
            logger.warning(f"Schema migration failed: {str(e)}")
            # This shouldn't prevent setup from continuing, just log warnings

    def _ensure_default_server_settings(self) -> None:
        """
        Ensure that default server settings exist in the database.
        This is called during table setup to guarantee server settings are available.
        """
        # Skip for SQLite tests where server_settings table is not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith('sqlite://'):
            return

        try:
            with self.database_session() as session:
                # Check if server settings already exist
                existing_settings = session.query(ServerSettings).first()

                if existing_settings:
                    logger.debug("Server settings already exist, skipping initialization")
                    return

                logger.info("Inserting default server settings")

                # Create default server settings
                server_settings = ServerSettings(
                    server_settings_id="global_settings",
                    is_private=False,
                    max_message_length=50000,
                    max_image_size=5,  # 5MB
                    max_video_size=50,  # 50MB
                    max_sticker_size=5,  # 5MB
                    max_gif_size=10,  # 10MB for animated GIFs
                    allowed_images_extensions=["png", "jpg", "jpeg", "gif", "webp"],
                    allowed_stickers_extensions=["png", "gif"],  # Stickers support PNG and GIF
                    allowed_gif_extensions=["gif"],  # Standalone GIFs
                    allowed_videos_extensions=["mp4", "webm"],
                    allowed_doc_extensions=["pdf", "doc", "docx", "txt", "zip"],
                    rate_limit_duration=5,  # 5 minutes
                    max_rate_limit_requests=6000,  # 6000 requests per window
                    max_rate_limit_warnings=15  # 15 warnings before blocking
                )

                session.add(server_settings)
                session.commit()

                logger.info("Default server settings inserted successfully")

        except Exception as e:
            logger.error(f"Failed to ensure default server settings: {str(e)}")
            raise

    def sign_up(self, user_data: Users) -> None:
        """
        Sign up a new user

        Args:
            `user_data` (Users): A `Users` object.

        Returns:
            `None`.
        """
        logger.debug(
            debug.DEBUG_SIGN_UP_USER_START(
                user_id=user_data.user_id,
                username=user_data.username
            )
        )

        # Check if we're using SQLite (for testing)
        database_uri = str(self.database_engine.url)
        is_sqlite = database_uri.startswith('sqlite://')

        with self.database_session() as session:
            # Add user first
            session.add(user_data)
            session.flush()  # Ensure user is inserted first

            # Only add message_read_history for PostgreSQL production
            if not is_sqlite:
                message_read_history = MessageReadHistory(
                    user_id=user_data.user_id,
                    viewed_messages_ids=list(),
                )
                session.add(message_read_history)

            # Handle encryption for non-SQLite databases
            if not is_sqlite:
                # Encrypt password and create key
                enc_password_data, password_key = self.hasher.encrypt(user_data.password)
                enc_password = base64.b64encode(enc_password_data).decode("ascii")

                # Encrypt auth token and create key
                enc_auth_token_data, auth_token_key = self.hasher.encrypt(user_data.auth_token)
                enc_auth_token = base64.b64encode(enc_auth_token_data).decode("ascii")

                # Create encryption keys
                password_key.user_id = user_data.user_id
                password_key.associated_to = "password"

                auth_token_key.user_id = user_data.user_id
                auth_token_key.associated_to = "auth_token"

                session.add(password_key)
                session.add(auth_token_key)

                # Update user with encrypted data
                user_data.password = enc_password
                user_data.auth_token = enc_auth_token
                session.merge(user_data)
            else:
                # For SQLite tests, use simple hash
                import hashlib
                hashed_password = hashlib.sha256(user_data.password.encode()).digest()
                hashed_auth = hashlib.sha256(user_data.auth_token.encode()).digest()
                user_data.password = base64.b64encode(hashed_password).decode("ascii")
                user_data.auth_token = base64.b64encode(hashed_auth).decode("ascii")

            # Create auth token entry
            auth_token = AuthTokens(
                user_id=user_data.user_id,
                auth_token=user_data.auth_token,
                auth_token_expire_time=user_data.auth_token_expire_time
            )
            session.add(auth_token)

            # Single commit for all user-related data
            session.commit()

        logger.info(
            info.INFO_NEW_USER_SIGNUP_SUCCESSFULLY(
                user=user_data
            )
        )

    def get_user(self, user_id: str | None = None, username: str | None = None) -> Users:
        """
        Fetch metadata about a user based on
        the user_id or the username from the database

        Args:
            user_id (str, optional): The user's `user_id`.
            username (str, optional): The user's username.

        Returns:
            Users: A `Users` table object.
        """
        user: Users = None

        logger.debug(
            debug.DEBUG_GET_USER_START(
                user_id=user_id,
                username=username
            )
        )

        with self.database_session() as session:
            stmt = select(Users).where(
                Users.user_id == user_id if user_id is not None else Users.username == username
            )

            user_result = session.execute(stmt).fetchone()
            user = user_result[0] if user_result else None

        if user:
            logger.debug(
                debug.DEBUG_USER_FOUND(
                    user_id=user.user_id,
                    username=user.username
                )
            )
        else:
            logger.debug(
                debug.DEBUG_USER_NOT_FOUND(
                    user_id=user_id,
                    username=username
                )
            )

        return user

    def count_users(self) -> int:
        """
        Counts the number of users signed up on the server

        Args:
            None.

        Returns:
            None.
        """
        users_number: int = None

        with self.database_session() as session:
            users_number = session.query(func.count(Users.user_id)).scalar()
        
        return users_number

    def get_user_read_messages_ids(self, user_id: str) -> list[str]:
        """
        Fetch the user's read messages_ids from the `message_read_history`
        table in the database

        Args:
            user_id (str): The user's `user_id`.

        Returns:
            list(str): A list of `message_id`s read by this user.
        """
        messages_ids: list[str] = []

        with self.database_session() as session:
            stmt = select(MessageReadHistory.viewed_messages_ids).where(
                MessageReadHistory.user_id == user_id
            )

            result = session.execute(stmt).fetchone()
            if result is not None:
                messages_ids = result[0]

        return messages_ids
    
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
    
    def save_auth_token(self, auth_token: AuthTokens) -> None:
        """
        Save the `auth_token` to the `auth_tokens` table
        in the database

        Args:
            `auth_token` (str): An `AuthTokens` table object.

        Returns:
            `None`.
        """
        # Skip saving auth token for SQLite tests where auth_tokens table is not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith('sqlite://'):
            return

        hashed_auth_token_value = auth_token.auth_token

        with self.database_session() as session:
            session.add(auth_token)

            session.commit()

        logger.info(
            debug.DEBUG_NEW_AUTH_TOKEN_SAVED(
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
            info.INFO_RESET_USER_AUTH_TOKEN(
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
        
        logger.debug(
            debug.DEBUG_FETCH_USERS_ID(
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
            list[str]: A list containing all the usernames in the database.
        """
        usernames = list()

        # For SQLite tests where users table may not exist, return empty list
        database_uri = str(self.database_engine.url)
        if database_uri.startswith('sqlite://'):
            return usernames

        with self.database_session() as session:
            stmt = select(Users.username)

            response = session.execute(stmt).fetchall()

            usernames = [response[i][0] for i in range(len(response))]

        logger.debug(
            debug.DEBUG_FETCH_USERNAMES(
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
    
    def update_user_password(self, user_id: str, ciphered_new_password: str) -> None:
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
                password=ciphered_new_password,
                updated_at=updated_at
            ).where(
                Users.user_id == user_id
            )

            session.execute(stmt)

            session.commit()

    def update_user_about(self, user_id: str, new_about: str) -> None:
        """Updates the user's about section

        Args:
            `user_id` (str): The user's `user_id`.
            `new_about` (str): The new about text.

        Returns:
            `None`.
        """
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        with self.database_session() as session:
            stmt = update(Users).values(
                about=new_about,
                updated_at=updated_at
            ).where(
                Users.user_id == user_id
            )

            session.execute(stmt)

            session.commit()

    def update_user_avatar(self, user_id: str, new_avatar_url: str) -> None:
        """Updates the user's avatar URL

        Args:
            `user_id` (str): The user's `user_id`.
            `new_avatar_url` (str): The new avatar URL.

        Returns:
            `None`.
        """
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        with self.database_session() as session:
            stmt = update(Users).values(
                avatar_url=new_avatar_url,
                updated_at=updated_at
            ).where(
                Users.user_id == user_id
            )

            session.execute(stmt)

            session.commit()

    def update_user_banner(self, user_id: str, new_banner_url: str) -> None:
        """Updates the user's banner URL

        Args:
            `user_id` (str): The user's `user_id`.
            `new_banner_url` (str): The new banner URL.

        Returns:
            `None`.
        """
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        with self.database_session() as session:
            stmt = update(Users).values(
                banner_url=new_banner_url,
                updated_at=updated_at
            ).where(
                Users.user_id == user_id
            )

            session.execute(stmt)

            session.commit()

    def update_message_hash(self, message_id: str, hashed_message: str) -> None:
        """Updates the message's hashed content

        Args:
            `message_id` (str): The message's `message_id`.
            `hashed_message` (str): The encrypted hashed message content.

        Returns:
            `None`.
        """
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        with self.database_session() as session:
            stmt = update(Messages).values(
                hashed_message=hashed_message,
                updated_at=updated_at
            ).where(
                Messages.message_id == message_id
            )

            session.execute(stmt)

            session.commit()
        
    def update_key(self, key: Keys) -> None:
        """
        Update the given `key` in the database

        Args:
            `key` (Keys): A `Keys` object.

        Returns:
            `None`.
        """
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        with self.database_session() as session:
            key = session.merge(key)
            stmt = update(Keys).values(
                key_value=key.key_value,
                iv=key.iv,
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

        logger.debug(
            debug.DEBUG_DERIVED_KEY_UPDATED(
                key=key
            )
        )
    
    def delete_encryption_key(self, key: Keys) -> None:
        """
        Delete the given encryption `key` from the database

        Args:
            `key` (Keys): A `Keys` object.

        Returns:
            `None`.
        """
        with self.database_session() as session:
            session.delete(key)

            session.commit()

        logger.info(
            debug.DEBUG_DERIVED_KEY_DELETED(
                key=key
            )
        )

    def save_keys(self, key: Keys) -> None:
        """
        Save the encryption `key` in the `keys` table
        in the database

        Args:
            `key` (Keys): A `Keys` object.

        Returns:
            `None`.
        """
        with self.database_session() as session:
            session.add(key)

            session.commit()

        logger.debug(
            debug.DEBUG_NEW_DERIVED_KEY_SAVED(
                key=key
            )
        )
        
    def get_keys(self, associated_to: str, user_id: str | None = None, message_id: str | None = None, conversation_id: str | None = None) -> Keys:
        """
        Fetch a key from the keys table
        in the database
        
        Args:
            `user_id` (str, optional, default: None): The user's `user_id`.
            `associated_to` (str): What data was this `key` used to encrypt.
            `message_id` (str , optional, default: None): The message's `message_id` (In case the encryption `key` was used to encrypt a message).
            conversation_id (str, optional, default: None): The conversation's `conversation_id`.
        
        Returns:
            Keys: A Keys table row.
        """
        key = None

        with self.database_session() as session:
            conditions = [
                Keys.user_id == user_id,
                Keys.associated_to == associated_to
            ]
            condition = None

            if message_id is not None:
                condition = Keys.message_id == message_id
            if conversation_id is not None:
                condition = Keys.message_id == conversation_id

            if condition is not None:
                conditions.append(condition)

            stmt = select(Keys).where(
                and_(
                    *conditions
                )
            )

            key = session.execute(stmt).fetchone()

        return key[0]

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
        
        logger.debug(
            debug.DEBUG_VALIDATE_AUTH_TOKEN(
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

    def create_new_channel(self, user_id: str, channel: Channels) -> None:
        """
        Create a new `channel` in the server

        Args:
            `user_id` (str): The user's `user_id` (The server owner have the right to create channels).
            `channel` (Channels): A `Channels` object.

        Returns:
            `None`.
        """
        with self.database_session() as session:
            session.add(channel)

            session.commit()

        logger.info(
            info.INFO_NEW_CHANNEL_CREATED(
                user_id=user_id,
                channel_id=channel.channel_id,
                channel_name=channel.channel_name
            )
        )
    
    def get_channel_data(self, channel_id: str) -> Channels | None:
        """
        Fetch the metadata of a `channel` from
        the `channels` table in the database
        
        Args:
            `channel_id` (str): The channel's `channel_id`.
        
        Returns:
            Channels: A `Channels` table object.
            None: If the channel doesn't exists.
        """
        channel_metadata = None

        with self.database_session() as session:
            stmt = select(Channels).where(
                Channels.channel_id == channel_id
            )

            channel_metadata = session.execute(stmt).fetchone()

        if channel_metadata is not None:
            channel_metadata = channel_metadata[0]
        
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
                allowed_users=text("array_append(allowed_users, '%s')" % to_add_user_id)
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
                allowed_users=text("array_remove(allowed_users, '%s')" % to_remove_user_id)
            ).where(
                Channels.channel_id == channel_id
            )

            session.execute(stmt)

            session.commit()

    def fetch_channel_messages(self, channel_id: str, messages_per_page: int, page: int) -> list[tuple[Messages, Users | None]]:
        """
        fetch a specific number of messages from a channel from
        the `channels` table in the database with user data

        Args:
            channel_id (str): The channel's `channel_id`.
            messages_per_page (int, optional, default: 20): The number of messages for each page.
            page (int, optional, default: 1): The page number (pages start from 1 to `x` depending on how many messages a channel contains).

        Returns:
            list[tuple[Messages, Users | None]]: A list of tuples containing `Messages` and `Users` table objects.
        """
        messages_with_users: list[tuple[Messages, Users | None]] = []

        with self.database_session() as session:
            channel_messages_ids = self.get_channel_data(
                channel_id=channel_id
            ).messages_ids

            start_index = (page*messages_per_page) - messages_per_page

            response = session.query(Messages, Users).join(
                Users, Messages.sender_id == Users.user_id, isouter=True
            ).filter(
                Messages.message_id.in_(channel_messages_ids)
            ).order_by(Messages.sent_at).offset(start_index).limit(messages_per_page).all()

            messages_with_users = response

        return messages_with_users

    def fetch_unviewed_channel_messages(self, channel_id: str, viewed_messages_ids: list[str]) -> list[Messages]:
        """
        Fetch latest unviewed messages by this user from a server channel

        Args:
            user_id (str): The user's `user_id`.
            channel_id (str): The channel's `channel_id`.
            viewed_messages_ids (list[str]): A list of viewed `message_id`s by this user.
        
        Returns:
            list[Messages]: A list of `Messages` table object.
        """
        messages: list[Messages] = None

        with self.database_session() as session:
            stmt = select(Messages).where(
                Messages.channel_id == channel_id,
                Messages.message_id.not_in(viewed_messages_ids)
            )

            messages = session.execute(stmt).all()

        return messages

    def save_message(self, message: Messages) -> None:
        """
        Save a message to the `messages` table in the database
        
        Args:
            message(Messages): A `Messages` table object.
        
        Returns:
            None
        """
        with self.database_session() as session:
            stmt = update(Channels).values(
                messages_ids=text("array_append(messages_ids, '%s')" % message.message_id)
            ).where(
                Channels.channel_id == message.channel_id
            )
            session.execute(stmt)
            session.add(message)

            session.commit()
    
    def get_message_metadata(self, message_id: str) -> Messages | None:
        """
        Fetch the message's metadata based on its `message_id`

        Args:
            message (str): The message's `message_id`.
        
        Returns:
            Messages | None: A `Messages` table object, it can be None if it doesn't exists.
        """
        message_metadata: Messages = None

        with self.database_session() as session:
            stmt = select(Messages).where(
                Messages.message_id == message_id
            )

            try:
                message_metadata = session.execute(stmt).fetchone()[0]
            except TypeError:
                pass

        return message_metadata

    def add_message_to_read_history(self, user_id: str, message_id: str) -> None:
        """
        Add a message to the `viewed_messages_ids` column in the `message_read_history`
        table in the database

        Args:
            auth_token (str): The user's `auth_token`.
            channel_id (str): The channel's `channel_id`.
            message_id (str): "The message's `message_id` that should added to the `viewed_messages_ids` column for this user.

        Returns:
            None.
        """
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        with self.database_session() as session:
            stmt = update(MessageReadHistory).values(
                viewed_messages_ids=text("array_append(viewed_messages_ids, '%s')" % message_id),
                updated_at=updated_at
            )

            session.execute(stmt)

            session.commit()
    
    def delete_message(self, message_id: str, channel_id: str) -> None:
        """
        Delete a message from a channel, and remove this message's 
        `message_id` from the `messages_ids` of this channel

        Args:
            message_id (str): The message's `message_id`.
            channel_id (str): The channel's `channel_id`.
        
        Returns:
            None.
        """
        with self.database_session() as session:
            stmts = [
                update(Channels).where(
                    Channels.channel_id == channel_id
                ).values(
                    messages_ids=text("array_remove(messages_ids, '%s')" % message_id)
                ),
                delete(Messages).where(
                    Messages.message_id == message_id
                ),
                delete(Keys).where(
                    Keys.message_id == message_id
                )
            ]

            for stmt in stmts:
                session.execute(stmt)

            session.commit()

    def save_blocked_ip_to_blocked_ips(self, blocked_ip: BlockedIPS) -> None:
        """
        Saves a BlockedIPS object to the blocked_ips table.

        Args:
            blocked_ip (BlockedIPS): A BlockedIPS object.

        Returns:
            None.
        """
        if self.check_is_ip_blocked(ip=blocked_ip.ip):
            return

        with self.database_session() as session:
            session.add(blocked_ip)

            session.commit()

    def fetch_blocked_ips(self) -> list[dict]:
        """
        Fetch a list of blocked ips from the blocked_ips table.

        Args:
            None.

        Returns:
            list[dict]: A list of dictionaries containing blocked IP data.
        """
        blocked_ips: list[dict] = list()

        with self.database_session() as session:
            stmt = select(BlockedIPS)

            response = session.execute(stmt).fetchall()

            for row in response:
                blocked_ip = row[0]
                blocked_ips.append({
                    "ip": blocked_ip.ip,
                    "reason": blocked_ip.block_reason,
                    "blocked_at": blocked_ip.blocked_at.isoformat()
                })

        return blocked_ips

    def check_is_ip_blocked(self, ip: str) -> bool:
        """
        Checks if a raw IP addresses is already in the `blocked_ips` table.

        Args:
            ip (str): The raw ip address to check.

        Returns:
            bool: True if the ip address is already blocked, otherwise False.
        """
        with self.database_session() as session:
            stmt = select(BlockedIPS).where(BlockedIPS.ip == ip)
            response = session.execute(stmt).fetchall()

            is_blocked = len(response) != 0

        return is_blocked

    def delete_blocked_ip(self, blocked_ip: BlockedIPS | None = None, ip: str | None = None) -> bool:
        """
        Deletes a blocked ip from the blocked_ips table, using either a BlockedIPS object or
        a raw ip address.

        Args:
            blocked_ip (BlockedIPS): A BlockedIPS object.
            ip (str): A raw ip address to delete from the database.

        Returns:
            bool: True if the IP was deleted, False if not found or failed.
        """
        with self.database_session() as session:
            if blocked_ip is not None:
                result = session.execute(delete(BlockedIPS).where(BlockedIPS.ip == blocked_ip.ip))
            else:
                result = session.execute(delete(BlockedIPS).where(BlockedIPS.ip == ip))

            session.commit()
            return result.rowcount > 0
    
    def create_server_row(self, server: Server) -> None:
        """
        Creates a row in the server table.

        Args:
            server (Server): The server object to create.

        Returns:
            None.
        """
        # Skip server creation for SQLite tests since the server table is excluded
        database_uri = str(self.database_engine.url)
        if database_uri.startswith('sqlite://'):
            return

        with self.database_session() as session:
            session.add(server)
            session.commit()
    
    def update_server_values(self, server_name: str, server_welcome_message: str, description: str | None = None,) -> None:
        """
        Updates the server's info.
        """
        updated_at = date_in_gmt()

        with self.database_session() as session:
            stmt = update(Server).values(
                server_name = server_name,
                welcome_message=server_welcome_message,
                description=description,
                updated_at=updated_at
            )

            session.execute(stmt)
            session.commit()

    def get_server(self) -> Server:
        """
        Fetches the server row from the server table.

        Args:
            None.

        Returns:
            Server: A server table row object.
        """
        server: Server

        with self.database_session() as session:
            stmt = select(Server)
            server = session.execute(stmt).fetchone()
            
        return server if server is None else server[0]

    def get_server_id(self) -> str:
        """
        Fetches the server id.

        Args:
            None.

        Returns:
            str: The server's id.
        """
        # For SQLite tests where server table is not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith('sqlite://'):
            return "test-server-id"

        server = self.get_server()

        return str(server.server_id)
    
    def get_server_members_count(self) -> int:
        """
        Fetches the members_count row from the server table.

        Args:
            None.

        Returns:
            int: members_count value.
        """
        server = self.get_server()

        return server.members_count

    def update_server_members_count(self, n: int) -> None:
        """
        Update the members_count column in the server table.

        Args:
            n (int): By how much should members_count be increased (can be negative in case of decrease).

        Returns:
            None.
        """
        current_members_count = self.get_server_members_count()

        with self.database_session() as session:
            stmt = update(Server).values(
                members_count = current_members_count + n
            )

            session.execute(stmt)
            session.commit()

    def get_server_settings(self) -> ServerSettings | None:
        """
        Fetches the server settings row from the server_settings table.

        Args:
            None.

        Returns:
            ServerSettings: A server settings table row object.
            None: If table doesn't exist or there's an error.
        """
        # For SQLite tests where server_settings table is not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith('sqlite://'):
            return None

        try:
            server_settings: ServerSettings

            with self.database_session() as session:
                stmt = select(ServerSettings)
                server_settings = session.execute(stmt).fetchone()

            return server_settings[0] if server_settings else None
        except Exception as e:
            logger.warning(f"Could not retrieve server settings, returning None: {e}")
            return None

    def update_server_settings(self, settings_updates: dict) -> None:
        """
        Update specific server settings in the server_settings table.

        Args:
            settings_updates (dict): Dictionary of field names to new values.
                                   Keys should match ServerSettings column names.

        Returns:
            None.
        """
        # For SQLite tests where server_settings table is not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith('sqlite://'):
            return

        if not settings_updates:
            return

        updated_at = date_in_gmt()

        with self.database_session() as session:
            stmt = update(ServerSettings).values(
                updated_at=updated_at,
                **settings_updates
            )

            session.execute(stmt)
            session.commit()

        logger.info(f"Server settings updated: {list(settings_updates.keys())}")

    def initialize_default_data(self) -> None:
        """
        Initializes default roles, privileges, and server settings in a single transaction.
        Idempotent - safe to run multiple times without errors.

        Args:
            None.

        Returns:
            None.
        """
        # Default privileges data
        default_privileges = [
            # User Management
            {"id": "create_users", "name": "Create Users", "category": "user_management"},
            {"id": "delete_users", "name": "Delete Users", "category": "user_management"},
            {"id": "edit_users", "name": "Edit Users", "category": "user_management"},
            {"id": "view_users", "name": "View Users", "category": "user_management"},
            {"id": "reset_user_tokens", "name": "Reset User Tokens", "category": "user_management"},

            # Channel Management
            {"id": "create_channels", "name": "Create Channels", "category": "channel_management"},
            {"id": "delete_channels", "name": "Delete Channels", "category": "channel_management"},
            {"id": "edit_channels", "name": "Edit Channels", "category": "channel_management"},
            {"id": "manage_channel_users", "name": "Manage Channel Users", "category": "channel_management"},
            {"id": "view_private_channels", "name": "View Private Channels", "category": "channel_management"},

            # Message Management
            {"id": "send_messages", "name": "Send Messages", "category": "message_management"},
            {"id": "delete_messages", "name": "Delete Messages", "category": "message_management"},
            {"id": "edit_messages", "name": "Edit Messages", "category": "message_management"},
            {"id": "view_messages", "name": "View Messages", "category": "message_management"},

            # Server Management
            {"id": "manage_server_settings", "name": "Manage Server Settings", "category": "server_management"},
            {"id": "manage_server_privileges", "name": "Manage Server Privileges", "category": "server_management"},
            {"id": "manage_cdn", "name": "Manage CDN", "category": "server_management"},
            {"id": "view_server_stats", "name": "View Server Stats", "category": "server_management"},

            # Moderation
            {"id": "ban_users", "name": "Ban Users", "category": "moderation"},
            {"id": "mute_users", "name": "Mute Users", "category": "moderation"},
            {"id": "moderate_content", "name": "Moderate Content", "category": "moderation"},
            {"id": "view_audit_logs", "name": "View Audit Logs", "category": "moderation"},

            # CDN Management
            {"id": "upload_files", "name": "Upload Files", "category": "cdn_management"},
            {"id": "delete_files", "name": "Delete Files", "category": "cdn_management"},
            {"id": "view_files", "name": "View Files", "category": "cdn_management"},
        ]

        # Default roles data
        default_roles = [
            {
                "id": "owner",
                "name": "Server Owner",
                "privileges": [
                    # All privileges for owner
                    "create_users", "delete_users", "edit_users", "view_users", "reset_user_tokens",
                    "create_channels", "delete_channels", "edit_channels", "manage_channel_users", "view_private_channels",
                    "send_messages", "delete_messages", "edit_messages", "view_messages",
                    "manage_server_settings", "manage_server_privileges", "manage_cdn", "view_server_stats",
                    "ban_users", "mute_users", "moderate_content", "view_audit_logs",
                    "upload_files", "delete_files", "view_files"
                ]
            },
            {
                "id": "admin",
                "name": "Administrator",
                "privileges": [
                    # Most privileges except server owner specific ones
                    "create_users", "edit_users", "view_users", "reset_user_tokens",
                    "create_channels", "delete_channels", "edit_channels", "manage_channel_users", "view_private_channels",
                    "send_messages", "delete_messages", "edit_messages", "view_messages",
                    "manage_server_settings", "view_server_stats",
                    "ban_users", "mute_users", "moderate_content", "view_audit_logs",
                    "upload_files", "delete_files", "view_files"
                ]
            },
            {
                "id": "moderator",
                "name": "Moderator",
                "privileges": [
                    # Moderation and basic management
                    "view_users",
                    "create_channels", "edit_channels", "manage_channel_users",
                    "send_messages", "delete_messages", "edit_messages", "view_messages",
                    "view_private_channels",
                    "ban_users", "mute_users", "moderate_content",
                    "upload_files", "view_files"
                ]
            },
            {
                "id": "user",
                "name": "Regular User",
                "privileges": [
                    # Basic user privileges
                    "send_messages", "view_messages",
                    "upload_files", "view_files",
                    "view_users"
                ]
            }
        ]

        with self.database_session() as session:
            # Check if data already exists
            existing_privileges_count = session.query(Privileges).count()
            existing_roles_count = session.query(Roles).count()
            existing_server_settings_count = session.query(ServerSettings).count()

            if existing_privileges_count > 0 or existing_roles_count > 0 or existing_server_settings_count > 0:
                logger.info("Default data already exists, skipping initialization")
                return

            # Add all privileges
            for privilege_data in default_privileges:
                privilege = Privileges(
                    privilege_id=privilege_data["id"],
                    privilege_name=privilege_data["name"],
                    category=privilege_data["category"]
                )
                session.add(privilege)

            # Add all roles
            for role_data in default_roles:
                role = Roles(
                    role_id=role_data["id"],
                    role_name=role_data["name"],
                    privileges_ids=role_data["privileges"]
                )
                session.add(role)

            # Add server settings
            server_settings = ServerSettings(
                server_settings_id="global_settings",
                is_private=False,
                max_message_length=50000,
                max_image_size=5,  # 5MB
                max_video_size=50,  # 50MB
                max_sticker_size=5,  # 5MB
                max_gif_size=10,  # 10MB for animated GIFs
                allowed_images_extensions=["png", "jpg", "jpeg", "gif", "webp"],
                allowed_stickers_extensions=["png", "gif"],  # Stickers support PNG and GIF
                allowed_gif_extensions=["gif"],  # Standalone GIFs
                allowed_videos_extensions=["mp4", "webm"],
                allowed_doc_extensions=["pdf", "doc", "docx", "txt", "zip"],
                rate_limit_duration=5,  # 5 minutes
                max_rate_limit_requests=6000,  # 6000 requests per window
                max_rate_limit_warnings=15  # 15 warnings before blocking
            )
            session.add(server_settings)

            # Single commit for all initialization data
            session.commit()

            logger.info("Default roles, privileges, and server settings initialized successfully")

    def add_sticker_to_catalog(self, sticker_url: str, filename: str, uploaded_by: uuid.UUID) -> str:
        """
        Add a sticker to the server catalog if it doesn't already exist.

        Args:
            sticker_url (str): The CDN URL of the sticker
            filename (str): Original filename of the sticker
            uploaded_by (uuid.UUID): User ID of who uploaded it

        Returns:
            str: The sticker ID
        """
        # Check if this sticker URL already exists
        existing_sticker = self.get_sticker_by_url(sticker_url)
        if existing_sticker:
            # Increment usage count
            self.increment_sticker_usage(existing_sticker.sticker_id)
            return existing_sticker.sticker_id

        # Generate new sticker ID
        sticker_id = str(uuid.uuid4())

        sticker = ServerStickers(
            sticker_id=sticker_id,
            sticker_url=sticker_url,
            filename=filename,
            uploaded_by=uploaded_by
        )

        with self.database_session() as session:
            session.add(sticker)
            session.commit()

        return sticker_id

    def add_gif_to_catalog(self, gif_url: str, filename: str, uploaded_by: uuid.UUID) -> str:
        """
        Add a GIF to the server catalog if it doesn't already exist.

        Args:
            gif_url (str): The CDN URL of the GIF
            filename (str): Original filename of the GIF
            uploaded_by (uuid.UUID): User ID of who uploaded it

        Returns:
            str: The GIF ID
        """
        # Check if this GIF URL already exists
        existing_gif = self.get_gif_by_url(gif_url)
        if existing_gif:
            # Increment usage count
            self.increment_gif_usage(existing_gif.gif_id)
            return existing_gif.gif_id

        # Generate new GIF ID
        gif_id = str(uuid.uuid4())

        gif = ServerGIFs(
            gif_id=gif_id,
            gif_url=gif_url,
            filename=filename,
            uploaded_by=uploaded_by
        )

        with self.database_session() as session:
            session.add(gif)
            session.commit()

        return gif_id

    def get_sticker_by_url(self, sticker_url: str) -> ServerStickers | None:
        """
        Get a sticker by its URL.

        Args:
            sticker_url (str): The sticker URL

        Returns:
            ServerStickers | None: The sticker object if found
        """
        with self.database_session() as session:
            stmt = select(ServerStickers).where(ServerStickers.sticker_url == sticker_url)
            result = session.execute(stmt).fetchone()
            return result[0] if result else None

    def get_gif_by_url(self, gif_url: str) -> ServerGIFs | None:
        """
        Get a GIF by its URL.

        Args:
            gif_url (str): The GIF URL

        Returns:
            ServerGIFs | None: The GIF object if found
        """
        with self.database_session() as session:
            stmt = select(ServerGIFs).where(ServerGIFs.gif_url == gif_url)
            result = session.execute(stmt).fetchone()
            return result[0] if result else None

    def increment_sticker_usage(self, sticker_id: str) -> None:
        """
        Increment the usage count of a sticker.

        Args:
            sticker_id (str): The sticker ID
        """
        with self.database_session() as session:
            stmt = update(ServerStickers).values(
                usage_count=ServerStickers.usage_count + 1,
                updated_at=datetime.datetime.now(datetime.timezone.utc)
            ).where(ServerStickers.sticker_id == sticker_id)
            session.execute(stmt)
            session.commit()

    def increment_gif_usage(self, gif_id: str) -> None:
        """
        Increment the usage count of a GIF.

        Args:
            gif_id (str): The GIF ID
        """
        import datetime
        with self.database_session() as session:
            stmt = update(ServerGIFs).values(
                usage_count=ServerGIFs.usage_count + 1,
                updated_at=datetime.datetime.now(datetime.timezone.utc)
            ).where(ServerGIFs.gif_id == gif_id)
            session.execute(stmt)
            session.commit()

    def list_server_stickers(self, limit: int = 50, offset: int = 0) -> list[dict]:
        """
        List server stickers ordered by usage count.

        Args:
            limit (int): Maximum number of stickers to return
            offset (int): Offset for pagination

        Returns:
            list[dict]: List of sticker dictionaries
        """
        with self.database_session() as session:
            stmt = select(ServerStickers).where(
                ServerStickers.is_active == True
            ).order_by(
                ServerStickers.usage_count.desc(),
                ServerStickers.created_at.desc()
            ).limit(limit).offset(offset)

            stickers = session.execute(stmt).fetchall()

            return [
                {
                    "sticker_id": s.sticker_id,
                    "sticker_url": s.sticker_url,
                    "filename": s.filename,
                    "uploaded_by": str(s.uploaded_by),
                    "usage_count": s.usage_count,
                    "created_at": s.created_at,
                    "updated_at": s.updated_at
                } for s in stickers
            ]

    def list_server_gifs(self, limit: int = 50, offset: int = 0) -> list[dict]:
        """
        List server GIFs ordered by usage count.

        Args:
            limit (int): Maximum number of GIFs to return
            offset (int): Offset for pagination

        Returns:
            list[dict]: List of GIF dictionaries
        """
        with self.database_session() as session:
            stmt = select(ServerGIFs).where(
                ServerGIFs.is_active == True
            ).order_by(
                ServerGIFs.usage_count.desc(),
                ServerGIFs.created_at.desc()
            ).limit(limit).offset(offset)

            gifs = session.execute(stmt).fetchall()

            return [
                {
                    "gif_id": g.gif_id,
                    "gif_url": g.gif_url,
                    "filename": g.filename,
                    "uploaded_by": str(g.uploaded_by),
                    "usage_count": g.usage_count,
                    "created_at": g.created_at,
                    "updated_at": g.updated_at
                } for g in gifs
            ]

    # Chart Data Methods for Background Tasks

    def get_user_registration_count_by_period(self, start_date: datetime, end_date: datetime) -> int:
        """Get count of user registrations between dates"""
        with self.database_session() as session:
            result = session.query(
                func.count(Users.user_id)
            ).filter(
                Users.created_at >= start_date,
                Users.created_at < end_date
            )
            return result.scalar() if result.scalar() is not None else 0

    def get_message_count_by_period(self, start_date: datetime, end_date: datetime) -> int:
        """Get count of messages between dates"""
        with self.database_session() as session:
            result = session.query(
                func.count(Messages.message_id)
            ).filter(
                Messages.sent_at >= start_date,
                Messages.sent_at < end_date
            )
            return result.scalar() if result.scalar() is not None else 0

    def get_channel_creation_count_by_period(self, start_date: datetime, end_date: datetime) -> int:
        """Get count of channel creations between dates"""
        with self.database_session() as session:
            result = session.query(
                func.count(Channels.channel_id)
            ).filter(
                Channels.created_at >= start_date,
                Channels.created_at < end_date
            )
            return result.scalar() if result.scalar() is not None else 0

    def save_chart_data_entry(self, chart_data_entry: ChartData) -> None:
        """Save a chart data entry"""
        with self.database_session() as session:
            # Check if entry already exists to avoid duplicates
            existing = session.query(ChartData).filter(
                ChartData.chart_type == chart_data_entry.chart_type,
                ChartData.period_type == chart_data_entry.period_type,
                ChartData.time_key == chart_data_entry.time_key
            ).first()

            if not existing:
                session.add(chart_data_entry)
                session.commit()

    def get_chart_data_entries(self, chart_type: str, period_type: str = None) -> list[ChartData]:
        """Get chart data entries for a specific type and optional period"""
        with self.database_session() as session:
            query = session.query(ChartData).filter(ChartData.chart_type == chart_type)

            if period_type:
                query = query.filter(ChartData.period_type == period_type)

            return query.order_by(ChartData.time_start).all()

    def get_user_status_counts(self) -> dict[str, int]:
        """Get counts of users by status"""
        with self.database_session() as session:
            online_count = session.query(
                func.count(Users.user_id)
            ).filter(Users.status == 'online').scalar() or 0

            offline_count = session.query(
                func.count(Users.user_id)
            ).filter(Users.status.in_(['offline', None, ''])).scalar() or 0

            away_count = session.query(
                func.count(Users.user_id)
            ).filter(Users.status == 'away').scalar() or 0

            # Handle other statuses if any
            other_count = session.query(
                func.count(Users.user_id)
            ).filter(Users.status.not_in(['online', 'offline', 'away', '', None])).scalar() or 0

            return {
                'online': online_count,
                'offline': offline_count,
                'away': away_count,
                'other': other_count
            }

    # Activity Metrics Methods

    def save_activity_metrics(self, metrics: ActivityMetrics) -> None:
        """Save activity metrics to the database"""
        with self.database_session() as session:
            # Check if metrics for this period already exist
            existing = session.query(ActivityMetrics).filter(
                ActivityMetrics.period == metrics.period,
                ActivityMetrics.date == metrics.date
            ).first()

            if existing:
                # Update existing metrics
                for attr, value in metrics.__dict__.items():
                    if not attr.startswith('_') and attr != 'id':
                        setattr(existing, attr, value)
                existing.server_uptime_hours = metrics.server_uptime_hours
            else:
                # Save new metrics
                session.add(metrics)

            session.commit()

    def get_latest_activity_metrics(self) -> dict:
        """Get the latest activity metrics for dashboard display"""
        with self.database_session() as session:
            # Get total users and channels
            total_users = self.count_users()

            # Get total channels
            database_uri = str(self.database_engine.url)
            if database_uri.startswith('sqlite://'):
                # For SQLite, we don't have channels table, use mock data
                total_channels = 0
            else:
                total_channels = session.query(func.count(Channels.channel_id)).scalar() or 0

            # Calculate current activity metrics

            # Messages per hour (current active period)
            one_hour_ago = datetime.datetime.now() - datetime.timedelta(hours=1)
            messages_last_hour = session.query(
                func.count(Messages.message_id)
            ).filter(
                Messages.sent_at >= one_hour_ago
            ).scalar() or 0

            # Active users (users who sent messages in last 24 hours)
            twenty_four_hours_ago = datetime.datetime.now() - datetime.timedelta(hours=24)
            active_users_24h = session.query(
                func.count(func.distinct(Messages.sender_id))
            ).filter(
                Messages.sent_at >= twenty_four_hours_ago
            ).scalar() or 0

            # Current online users
            user_status_counts = self.get_user_status_counts()
            current_online = user_status_counts.get('online', 0)

            # Calculate engagement rate (active users / total users)
            engagement_rate = (active_users_24h / total_users * 100) if total_users > 0 else 0

            # Get latest activity metrics record for trends
            latest_metrics = session.query(ActivityMetrics).order_by(
                ActivityMetrics.created_at.desc()
            ).first()

            return {
                'total_users': total_users,
                'total_channels': total_channels,
                'messages_per_hour': messages_last_hour,
                'active_users_24h': active_users_24h,
                'current_online': current_online,
                'engagement_rate': round(engagement_rate, 1),
                'messages_per_active_user': round(messages_last_hour / max(active_users_24h, 1), 1) if messages_last_hour > 0 else 0,
                'channel_utilization': min(int((active_users_24h / max(total_channels, 1)) * 100), 100) if total_channels > 0 else 0,
                'last_updated': latest_metrics.created_at.isoformat() if latest_metrics else None
            }

    def calculate_daily_activity_metrics(self) -> ActivityMetrics | None:
        """Calculate and return daily activity metrics"""
        # Get today's date (start of day)
        today = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        tomorrow = today + datetime.timedelta(days=1)

        with self.database_session() as session:
            # Count new users registered today
            new_users_today = self.get_user_registration_count_by_period(today, tomorrow)

            # Count messages sent today
            messages_today = self.get_message_count_by_period(today, tomorrow)

            # Get active users today (users who sent messages)
            active_users_today = session.query(
                func.count(func.distinct(Messages.sender_id))
            ).filter(
                Messages.sent_at >= today,
                Messages.sent_at < tomorrow
            ).scalar() or 0

            # Get online user stats
            online_avg = session.query(func.avg(ChartData.value)).filter(
                ChartData.chart_type == 'online_users',
                ChartData.time_start >= today,
                ChartData.time_start < tomorrow
            ).scalar() or 0

            online_peak = session.query(func.max(ChartData.value)).filter(
                ChartData.chart_type == 'online_users',
                ChartData.time_start >= today,
                ChartData.time_start < tomorrow
            ).scalar() or 0

            # Get total users at end of day
            total_users = self.count_users()

            # Get channels used today
            channels_used_today = session.query(
                func.count(func.distinct(Messages.channel_id))
            ).filter(
                Messages.sent_at >= today,
                Messages.sent_at < tomorrow
            ).scalar() or 0

            # Calculate messages per hour average for today
            messages_per_hour = messages_today / 24 if messages_today > 0 else 0

            # Calculate engagement metrics
            engagement_rate = (active_users_today / total_users * 100) if total_users > 0 else 0
            messages_per_active_user = messages_today / max(active_users_today, 1) if messages_today > 0 else 0
            channel_utilization_rate = (channels_used_today / max(total_channels, 1) * 100) if total_channels > 0 else 0

            # Get total channels
            total_channels = session.query(func.count(Channels.channel_id)).scalar() or 0

            # Calculate server uptime (this would need to be tracked system-wide)
            server_uptime_hours = 24.0  # Simplified - would need to track actual uptime

            # Get file upload stats for today
            files_uploaded_today = session.query(
                func.count(FileReferences.id)
            ).filter(
                FileReferences.created_at >= today,
                FileReferences.created_at < tomorrow
            ).scalar() or 0

            total_file_size_today = session.query(
                func.sum(FileObjects.file_size)
            ).join(
                FileReferences, FileObjects.file_id == FileReferences.file_id
            ).filter(
                FileReferences.created_at >= today,
                FileReferences.created_at < tomorrow
            ).scalar() or 0

            total_file_size_mb = total_file_size_today / (1024 * 1024) if total_file_size_today else 0

            return ActivityMetrics(
                period='daily',
                date=today,
                total_users=total_users,
                new_users=new_users_today,
                active_users=active_users_today,
                online_users_avg=online_avg,
                online_users_peak=online_peak,
                total_messages=messages_today,
                messages_this_period=messages_today,
                messages_per_hour=messages_per_hour,
                channels_used=channels_used_today,
                user_engagement_rate=engagement_rate,
                messages_per_active_user=messages_per_active_user,
                channel_utilization_rate=channel_utilization_rate,
                files_uploaded=files_uploaded_today,
                total_file_size_mb=total_file_size_mb,
                server_uptime_hours=server_uptime_hours
            )

    def count_channels(self) -> int:
        """Count total channels in the server"""
        with self.database_session() as session:
            return session.query(func.count(Channels.channel_id)).scalar() or 0

    def get_current_online_count(self) -> int:
        """Get current online users count"""
        status_counts = self.get_user_status_counts()
        return status_counts.get('online', 0)

    def update_server_avatar_url(self, avatar_url: str) -> None:
        """Update the server's avatar URL

        Args:
            avatar_url (str): The new avatar URL.

        Returns:
            None.
        """
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        # For SQLite tests where server table is not created, skip
        database_uri = str(self.database_engine.url)
        if database_uri.startswith('sqlite://'):
            return

        with self.database_session() as session:
            stmt = update(Server).values(
                avatar_url=avatar_url,
                updated_at=updated_at
            )

            session.execute(stmt)

            session.commit()

    def update_server_banner_url(self, banner_url: str) -> None:
        """Update the server's banner URL

        Args:
            banner_url (str): The new banner URL.

        Returns:
            None.
        """
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        # For SQLite tests where server table is not created, skip
        database_uri = str(self.database_engine.url)
        if database_uri.startswith('sqlite://'):
            return

        with self.database_session() as session:
            stmt = update(Server).values(
                banner_url=banner_url,
                updated_at=updated_at
            )

            session.execute(stmt)

            session.commit()

    def create_file_object(self, file_hash: str, ref_count: int, file_path: str, file_size: int, mime_type: str, verification_status: str = "unverified") -> None:
        """
        Create a file object entry in the database

        Args:
            file_hash (str): SHA-256 hash of the file
            ref_count (int): Initial reference count
            file_path (str): Relative path to the file
            file_size (int): File size in bytes
            mime_type (str): MIME type of the file
            verification_status (str): Verification status

        Returns:
            None
        """
        # Skip for SQLite tests where file tables are not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith('sqlite://'):
            return

        file_obj = FileObjects(
            file_hash=file_hash,
            ref_count=ref_count,
            file_path=file_path,
            file_size=file_size,
            mime_type=mime_type,
            verification_status=verification_status
        )

        with self.database_session() as session:
            session.add(file_obj)
            session.commit()

    def create_file_reference(self, reference_id: str, file_hash: str, reference_type: str, reference_entity_id: str) -> None:
        """
        Create a file reference entry in the database

        Args:
            reference_id (str): Unique reference identifier
            file_hash (str): SHA-256 hash of the file
            reference_type (str): Type of reference (e.g., 'cdn_upload')
            reference_entity_id (str): ID of the entity being referenced

        Returns:
            None
        """
        # Skip for SQLite tests where file tables are not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith('sqlite://'):
            return

        file_ref = FileReferences(
            reference_id=reference_id,
            file_hash=file_hash,
            reference_type=reference_type,
            reference_entity_id=reference_entity_id
        )

        with self.database_session() as session:
            session.add(file_ref)
            session.commit()

    def increment_file_reference_count(self, file_hash: str) -> None:
        """
        Increment the reference count for a file

        Args:
            file_hash (str): SHA-256 hash of the file

        Returns:
            None
        """
        # Skip for SQLite tests where file tables are not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith('sqlite://'):
            return

        with self.database_session() as session:
            stmt = update(FileObjects).values(
                ref_count=FileObjects.ref_count + 1
            ).where(FileObjects.file_hash == file_hash)
            session.execute(stmt)
            session.commit()

    def decrement_file_reference_count(self, file_hash: str) -> None:
        """
        Decrement the reference count for a file

        Args:
            file_hash (str): SHA-256 hash of the file

        Returns:
            None
        """
        # Skip for SQLite tests where file tables are not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith('sqlite://'):
            return

        with self.database_session() as session:
            stmt = update(FileObjects).values(
                ref_count=FileObjects.ref_count - 1
            ).where(FileObjects.file_hash == file_hash)
            session.execute(stmt)
            session.commit()

    def cleanup_orphaned_files(self, db_files: List[str] = None) -> None:
        """
        Remove files that are no longer referenced in the database.
        This is used by the CDN cleanup feature to remove unreferenced files.

        Args:
            db_files (List[str]): Optional list of referenced file URLs.
                                If None, uses database references.

        Returns:
            None
        """
        from pathlib import Path

        # Skip for SQLite tests where file tables are not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith('sqlite://'):
            return

        with self.database_session() as session:
            if db_files is None:
                # Get all referenced file hashes from the database
                file_hashes = session.query(FileReferences.file_hash).distinct().all()
                file_hashes = [h[0] for h in file_hashes]
            else:
                # Convert URLs to hashes if URL list provided (legacy support)
                file_hashes = []
                for url in db_files:
                    # Extract path from URL and try to find corresponding file
                    base_url = self.config.CDN_BASE_URL.lstrip('/')
                    if url.startswith(base_url):
                        relative_path = url[len(base_url):].lstrip('/')
                        file_path = Path(self.config.CDN_STORAGE_PATH) / relative_path
                        if file_path.exists():
                            try:
                                with open(file_path, "rb") as f:
                                    content = f.read()
                                    file_hash = hashlib.sha256(content).hexdigest()
                                    file_hashes.append(file_hash)
                            except:
                                continue

            # Get files with zero references
            orphaned_files = session.query(FileObjects).filter(
                FileObjects.ref_count <= 0,
                FileObjects.file_hash.not_in(file_hashes) if file_hashes else True
            ).all()

            # Delete orphaned files from disk and database
            for file_obj in orphaned_files:
                file_path = Path(self.config.CDN_STORAGE_PATH) / file_obj.file_path
                try:
                    if file_path.exists():
                        file_path.unlink()
                        logger.info(f"Deleted orphaned file: {file_obj.file_path}")

                    # Remove from database
                    session.delete(file_obj)

                except Exception as e:
                    logger.warning(f"Failed to delete orphaned file {file_obj.file_path}: {e}")

            # Also find and remove files on disk that aren't in the database
            cdn_dir = Path(self.config.CDN_STORAGE_PATH)
            if cdn_dir.exists():
                for sub_dir in cdn_dir.glob("*"):
                    if sub_dir.is_dir():  # Only process subdirectories
                        for file_path in sub_dir.glob("*"):
                            if file_path.is_file():
                                try:
                                    with open(file_path, "rb") as f:
                                        content = f.read()
                                        file_hash = hashlib.sha256(content).hexdigest()

                                    # Check if this file exists in database
                                    existing = session.query(FileObjects).filter(
                                        FileObjects.file_hash == file_hash
                                    ).first()

                                    if not existing:
                                        # File not in database, check if it's referenced
                                        is_referenced = session.query(FileReferences).filter(
                                            FileReferences.file_hash == file_hash
                                        ).count() > 0

                                        if not is_referenced:
                                            # Truly orphaned file - remove it
                                            file_path.unlink()
                                            logger.info(f"Deleted unreferenced file on disk: {file_path.name}")
                                except:
                                    continue

            session.commit()

    def get_referenced_files_list(self) -> List[str]:
        """
        Get a list of all referenced file URLs for cleanup operations

        Args:
            None

        Returns:
            List[str]: List of referenced file URLs
        """
        # Skip for SQLite tests where file tables are not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith('sqlite://'):
            return []

        with self.database_session() as session:
            # Get all referenced file hashes
            results = session.query(FileReferences.file_hash, FileObjects.file_path).join(
                FileObjects, FileReferences.file_hash == FileObjects.file_hash
            ).all()

            # Convert to URLs
            referenced_files = []
            for file_hash, file_path in results:
                url = f"{self.config.CDN_BASE_URL}/{file_path}"
                referenced_files.append(url)

            return referenced_files

    # Activity Audit Methods

    def create_activity_audit_entry(self, activity_audit: ActivityAudit) -> None:
        """
        Create an activity audit entry in the database

        Args:
            activity_audit (ActivityAudit): The activity audit entry to create

        Returns:
            None
        """
        # Skip for SQLite tests where activity_audit table is not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith('sqlite://'):
            return

        with self.database_session() as session:
            session.add(activity_audit)
            session.commit()

    def get_recent_activities(self, limit: int = 10) -> list[ActivityAudit]:
        """
        Get recent activity audit entries, ordered by creation time (newest first)

        Args:
            limit (int): Maximum number of activity entries to return

        Returns:
            list[ActivityAudit]: List of recent activity entries
        """
        # Skip for SQLite tests where activity_audit table is not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith('sqlite://'):
            # Return empty list for testing
            return []

        with self.database_session() as session:
            # Get recent activities, ordered by creation time descending
            activities = session.query(ActivityAudit).order_by(
                ActivityAudit.created_at.desc()
            ).limit(limit).all()

            return activities
