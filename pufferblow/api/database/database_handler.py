import base64
import datetime
import hashlib
import json
import uuid

import sqlalchemy
from loguru import logger
from sqlalchemy import and_, delete, func, select, text, update
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from pufferblow.api.database.metrics_files_mixin import DatabaseMetricsFilesMixin
from pufferblow.api.database.runtime_config_mixin import DatabaseRuntimeConfigMixin
from pufferblow.api.database.tables.activity_audit import ActivityAudit
from pufferblow.api.database.tables.activity_metrics import ActivityMetrics
from pufferblow.api.database.tables.activitypub import (
    ActivityPubActor,
    ActivityPubFollow,
    ActivityPubInboxActivity,
    ActivityPubOutboxActivity,
)
from pufferblow.api.database.tables.auth_tokens import AuthTokens
from pufferblow.api.database.tables.blocked_ips import BlockedIPS
from pufferblow.api.database.tables.channels import Channels
from pufferblow.api.database.tables.chart_data import ChartData
from pufferblow.api.database.tables.decentralized_sessions import (
    DecentralizedAuthChallenge,
    DecentralizedNodeSession,
)
from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.database.tables.file_objects import FileObjects, FileReferences
from pufferblow.api.database.tables.instance_runtime_config import InstanceRuntimeConfig
from pufferblow.api.database.tables.keys import Keys
from pufferblow.api.database.tables.message_read_history import MessageReadHistory
from pufferblow.api.database.tables.messages import Messages
from pufferblow.api.database.tables.privileges import Privileges
from pufferblow.api.database.tables.roles import Roles
from pufferblow.api.database.tables.server import Server
from pufferblow.api.database.tables.server_settings import ServerSettings
from pufferblow.api.database.tables.sticker_catalog import ServerGIFs, ServerStickers
from pufferblow.api.database.tables.voice_sessions import (
    VoiceJoinToken,
    VoiceSession,
    VoiceSessionEvent,
    VoiceSessionParticipant,
)
from pufferblow.api.database.tables.users import Users
from pufferblow.api.encrypt.encrypt import Encrypt
from pufferblow.api.logger.msgs import debug, info
from pufferblow.api.models.config_model import Config
from pufferblow.api.roles.constants import DEFAULT_ROLE_ID, IMMUTABLE_ROLE_IDS
from pufferblow.api.utils.current_date import date_in_gmt


class DatabaseHandler(DatabaseRuntimeConfigMixin, DatabaseMetricsFilesMixin):
    """Database handler for PufferBlow's API"""
    def __init__(
        self, database_engine: sqlalchemy.create_engine, encrypt_manager: Encrypt, config: Config
    ) -> None:
        """Initialize the instance."""
        self.database_engine = database_engine
        self.database_session = sessionmaker(
            bind=self.database_engine, expire_on_commit=False
        )
        self.encrypt_manager = encrypt_manager
        self.config = config

        self.setup_tables(base=Base)

    def _is_sqlite(self) -> bool:
        """Return True when the active engine is SQLite."""
        return str(self.database_engine.url).startswith("sqlite://")

    def setup_tables(self, base: DeclarativeBase) -> None:
        """
        Setup the needed database tables

        Args:
            `base` (DeclarativeBase): A `DeclarativeBase` sub-class.

        Returns:
            `None`.
        """
        is_sqlite = self._is_sqlite()

        # Test the connection first
        try:
            with self.database_engine.connect() as conn:
                logger.debug("Database connection successful")
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise

        if is_sqlite:
            logger.debug("Setting up SQLite tables for testing")
            # For SQLite tests, exclude PostgreSQL-specific tables and tables with unsupported features.
            postgresql_only_tables = {
                ServerSettings.__tablename__,
                # Tables with UUID columns that SQLite doesn't handle properly for tests
                "server_stickers",
                "server_gifs",
                # File reference system tables (for testing, we'll use basic hashing without references)
                "file_objects",
                "file_references",
                # Chart data table uses advanced date functions that SQLite doesn't handle well
                "chart_data",
                "decentralized_auth_challenges",
                "decentralized_node_sessions",
                "activitypub_actors",
                "activitypub_follows",
                "activitypub_inbox_activities",
                "activitypub_outbox_activities",
                # Note: 'users' table is now included for basic user operations with datetime compatibility
                # Note: 'blocked_ips' table is included for basic functionality
            }
            tables_to_create = [
                table
                for table in base.metadata.sorted_tables
                if table.name not in postgresql_only_tables
            ]
            logger.debug(
                f"Creating {len(tables_to_create)} tables: {[t.name for t in tables_to_create]}"
            )

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
                # Ensure runtime config keys exist
                self._ensure_default_runtime_config()
            except Exception as e:
                logger.error(f"PostgreSQL table creation failed: {e}")
                raise

    def _create_tables_safely(self, base: DeclarativeBase) -> None:
        """
        Create all declared tables in a single idempotent call.
        """
        try:
            base.metadata.create_all(self.database_engine)
            logger.debug("Table creation completed successfully")
        except Exception as e:
            logger.error(f"Table creation failed: {str(e)}")
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
                user_id=user_data.user_id, username=user_data.username
            )
        )

        is_sqlite = self._is_sqlite()

        with self.database_session() as session:
            # Add user first
            session.add(user_data)
            session.flush()  # Ensure user is inserted first

            message_read_history = MessageReadHistory(
                user_id=str(user_data.user_id) if is_sqlite else user_data.user_id,
                viewed_messages_ids=list(),
            )
            session.add(message_read_history)

            # Handle encryption for non-SQLite databases
            if not is_sqlite:
                # Encrypt password and create key
                enc_password_data, password_key = self.encrypt_manager.encrypt(
                    user_data.password
                )
                enc_password = base64.b64encode(enc_password_data).decode("ascii")

                # Encrypt auth token and create key
                enc_auth_token_data, auth_token_key = self.encrypt_manager.encrypt(
                    user_data.auth_token
                )
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
                auth_token_expire_time=user_data.auth_token_expire_time,
            )
            session.add(auth_token)

            # Single commit for all user-related data
            session.commit()

        logger.info(info.INFO_NEW_USER_SIGNUP_SUCCESSFULLY(user=user_data))

    def get_user(
        self, user_id: str | None = None, username: str | None = None
    ) -> Users:
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

        logger.debug(debug.DEBUG_GET_USER_START(user_id=user_id, username=username))

        normalized_user_id = user_id
        if user_id is not None and not isinstance(user_id, uuid.UUID):
            try:
                normalized_user_id = uuid.UUID(str(user_id))
            except (TypeError, ValueError):
                normalized_user_id = user_id

        with self.database_session() as session:
            stmt = select(Users).where(
                Users.user_id == normalized_user_id
                if normalized_user_id is not None
                else Users.username == username
            )

            user_result = session.execute(stmt).fetchone()
            user = user_result[0] if user_result else None

        if user:
            logger.debug(
                debug.DEBUG_USER_FOUND(user_id=user.user_id, username=user.username)
            )
        else:
            logger.debug(debug.DEBUG_USER_NOT_FOUND(user_id=user_id, username=username))

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
                messages_ids = result[0] or []

        return messages_ids

    def get_unread_message_counts_by_channel(
        self, user_id: str, channel_ids: list[str] | None = None
    ) -> dict[str, int]:
        """Return unread message counts grouped by channel for the given user."""
        if channel_ids is not None and len(channel_ids) == 0:
            return {}

        viewed_messages_ids = self.get_user_read_messages_ids(user_id)
        counts: dict[str, int] = {}

        with self.database_session() as session:
            query = session.query(
                Messages.channel_id,
                func.count(Messages.message_id),
            )

            if channel_ids:
                query = query.filter(Messages.channel_id.in_(channel_ids))

            if viewed_messages_ids:
                query = query.filter(Messages.message_id.not_in(viewed_messages_ids))

            rows = query.group_by(Messages.channel_id).all()
            for channel_id, count in rows:
                if channel_id:
                    counts[str(channel_id)] = int(count)

        return counts

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
                and_(AuthTokens.user_id == user_id, AuthTokens.auth_token == auth_token)
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
        if database_uri.startswith("sqlite://"):
            return

        hashed_auth_token_value = auth_token.auth_token

        with self.database_session() as session:
            session.add(auth_token)

            session.commit()

        logger.info(
            debug.DEBUG_NEW_AUTH_TOKEN_SAVED(auth_token=hashed_auth_token_value)
        )

    def save_refresh_token(
        self, user_id: str, token_hash: str, expires_at: datetime.datetime
    ) -> None:
        """
        Persist a refresh token hash for a user.
        """
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return

        row = AuthTokens(
            auth_token=f"refresh:{token_hash}",
            auth_token_expire_time=expires_at,
            user_id=uuid.UUID(str(user_id)),
            updated_at=datetime.datetime.now(datetime.timezone.utc),
        )

        with self.database_session() as session:
            session.add(row)
            session.commit()

    def get_refresh_token(self, token_hash: str) -> AuthTokens | None:
        """
        Fetch a non-expired refresh token row by hash.
        """
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return None

        now = datetime.datetime.now(datetime.timezone.utc)
        with self.database_session() as session:
            stmt = select(AuthTokens).where(
                and_(
                    AuthTokens.auth_token == f"refresh:{token_hash}",
                    AuthTokens.auth_token_expire_time > now,
                )
            )
            result = session.execute(stmt).fetchone()
            return result[0] if result else None

    def delete_refresh_token(self, token_hash: str) -> None:
        """
        Revoke a refresh token by deleting its row.
        """
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return

        with self.database_session() as session:
            stmt = delete(AuthTokens).where(
                AuthTokens.auth_token == f"refresh:{token_hash}"
            )
            session.execute(stmt)
            session.commit()

    def update_auth_token(
        self, user_id: str, new_auth_token: str, new_auth_token_expire_time: str
    ) -> None:
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
                update(AuthTokens)
                .values(
                    auth_token=new_auth_token,
                    auth_token_expire_time=new_auth_token_expire_time,
                    updated_at=updated_at,
                )
                .where(AuthTokens.user_id == user_id),
                update(Users)
                .values(
                    auth_token=new_auth_token,
                    auth_token_expire_time=new_auth_token_expire_time,
                    updated_at=updated_at,
                )
                .where(Users.user_id == user_id),
            ]
            for stmt in stmts:
                session.execute(stmt)

            session.commit()

        logger.info(
            info.INFO_RESET_USER_AUTH_TOKEN(
                user_id=user_id, new_hashed_auth_token=new_auth_token
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

        logger.debug(debug.DEBUG_FETCH_USERS_ID(users_id=users_id))

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

        with self.database_session() as session:
            stmt = select(Users.username)

            response = session.execute(stmt).fetchall()

            usernames = [response[i][0] for i in range(len(response))]

        logger.debug(debug.DEBUG_FETCH_USERNAMES(usernames=usernames))

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
            stmt = select(AuthTokens.updated_at).where(AuthTokens.user_id == user_id)

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
            stmt = (
                update(Users)
                .values(username=new_username, updated_at=updated_at)
                .where(Users.user_id == user_id)
            )

            session.execute(stmt)

            session.commit()

    def update_user_status(self, user_id: str, status: str) -> None:
        """Updates the user's status

        Args:
            `status` (str): The user's canonical status value.
            `last_seen` (str): Last seen time in GMT (in case the status="offline").

        Returns:
            `None`.
        """
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        with self.database_session() as session:
            stmts = []

            stmts.append(
                update(Users)
                .values(status=status, updated_at=updated_at)
                .where(Users.user_id == user_id)
            )

            if status == "offline":
                stmts.append(
                    update(Users)
                    .values(last_seen=date_in_gmt(format="%Y-%m-%d %H:%M:%S"))
                    .where(Users.user_id == user_id)
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
            stmt = (
                update(Users)
                .values(password=ciphered_new_password, updated_at=updated_at)
                .where(Users.user_id == user_id)
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
            stmt = (
                update(Users)
                .values(about=new_about, updated_at=updated_at)
                .where(Users.user_id == user_id)
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
            stmt = (
                update(Users)
                .values(avatar_url=new_avatar_url, updated_at=updated_at)
                .where(Users.user_id == user_id)
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
            stmt = (
                update(Users)
                .values(banner_url=new_banner_url, updated_at=updated_at)
                .where(Users.user_id == user_id)
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
            stmt = (
                update(Messages)
                .values(hashed_message=hashed_message, updated_at=updated_at)
                .where(Messages.message_id == message_id)
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
            stmt = (
                update(Keys)
                .values(
                    key_value=key.key_value,
                    iv=key.iv,
                    associated_to=key.associated_to,
                    updated_at=updated_at,
                )
                .where(
                    and_(
                        Keys.user_id == key.user_id,
                        Keys.associated_to == key.associated_to,
                    )
                )
            )

            session.execute(stmt)

            session.commit()

        logger.debug(debug.DEBUG_DERIVED_KEY_UPDATED(key=key))

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

        logger.info(debug.DEBUG_DERIVED_KEY_DELETED(key=key))

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

        logger.debug(debug.DEBUG_NEW_DERIVED_KEY_SAVED(key=key))

    def get_keys(
        self,
        associated_to: str,
        user_id: str | None = None,
        message_id: str | None = None,
        conversation_id: str | None = None,
    ) -> Keys:
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
            conditions = [Keys.user_id == user_id, Keys.associated_to == associated_to]
            condition = None

            if message_id is not None:
                condition = Keys.message_id == message_id
            if conversation_id is not None:
                condition = Keys.message_id == conversation_id

            if condition is not None:
                conditions.append(condition)

            stmt = select(Keys).where(and_(*conditions))

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
            stmt = select(AuthTokens.auth_token_expire_time).where(
                and_(AuthTokens.user_id == user_id, AuthTokens.auth_token == auth_token)
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
                    AuthTokens.auth_token == hashed_auth_token,
                )
            )

            reponse = session.execute(stmt).fetchall()

            if len(reponse) == 0:
                is_valid = not is_valid

        logger.debug(
            debug.DEBUG_VALIDATE_AUTH_TOKEN(
                hashed_auth_token=hashed_auth_token, is_valid=is_valid
            )
        )

        return is_valid

    def create_decentralized_auth_challenge(
        self,
        user_id: str,
        node_id: str,
        challenge_nonce: str,
        expires_at: datetime.datetime,
    ) -> DecentralizedAuthChallenge:
        """
        Create a one-time decentralized auth challenge.
        """
        challenge = DecentralizedAuthChallenge(
            user_id=uuid.UUID(str(user_id)),
            node_id=node_id,
            challenge_nonce=challenge_nonce,
            expires_at=expires_at,
        )

        with self.database_session() as session:
            session.add(challenge)
            session.commit()
            session.refresh(challenge)

        return challenge

    def get_decentralized_auth_challenge(
        self, challenge_id: str
    ) -> DecentralizedAuthChallenge | None:
        """
        Fetch a decentralized auth challenge by ID.
        """
        with self.database_session() as session:
            stmt = select(DecentralizedAuthChallenge).where(
                DecentralizedAuthChallenge.challenge_id == uuid.UUID(str(challenge_id))
            )
            result = session.execute(stmt).fetchone()
            return result[0] if result else None

    def consume_decentralized_auth_challenge(self, challenge_id: str) -> bool:
        """
        Mark a decentralized auth challenge as consumed.
        """
        with self.database_session() as session:
            stmt = (
                update(DecentralizedAuthChallenge)
                .values(consumed=True)
                .where(
                    DecentralizedAuthChallenge.challenge_id
                    == uuid.UUID(str(challenge_id))
                )
            )
            result = session.execute(stmt)
            session.commit()
            return (result.rowcount or 0) > 0

    def create_decentralized_node_session(
        self,
        user_id: str,
        node_id: str,
        node_public_key: str,
        session_token_hash: str,
        session_token_hint: str,
        expires_at: datetime.datetime,
        scopes: str = "chat:read,chat:write",
    ) -> DecentralizedNodeSession:
        """
        Create a decentralized node-bound session.
        """
        session_obj = DecentralizedNodeSession(
            user_id=uuid.UUID(str(user_id)),
            node_id=node_id,
            node_public_key=node_public_key,
            session_token_hash=session_token_hash,
            session_token_hint=session_token_hint,
            scopes=scopes,
            expires_at=expires_at,
        )

        with self.database_session() as session:
            session.add(session_obj)
            session.commit()
            session.refresh(session_obj)

        return session_obj

    def get_decentralized_node_session_by_hash(
        self, session_token_hash: str
    ) -> DecentralizedNodeSession | None:
        """
        Fetch an active decentralized node session by token hash.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        with self.database_session() as session:
            stmt = select(DecentralizedNodeSession).where(
                and_(
                    DecentralizedNodeSession.session_token_hash == session_token_hash,
                    DecentralizedNodeSession.revoked.is_(False),
                    DecentralizedNodeSession.expires_at > now,
                )
            )
            result = session.execute(stmt).fetchone()
            return result[0] if result else None

    def revoke_decentralized_node_session(self, session_id: str) -> bool:
        """
        Revoke a decentralized node session.
        """
        with self.database_session() as session:
            stmt = (
                update(DecentralizedNodeSession)
                .values(revoked=True)
                .where(DecentralizedNodeSession.session_id == uuid.UUID(str(session_id)))
            )
            result = session.execute(stmt)
            session.commit()
            return (result.rowcount or 0) > 0

    def list_active_decentralized_node_sessions(
        self, user_id: str
    ) -> list[DecentralizedNodeSession]:
        """
        List active decentralized sessions for a user.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        with self.database_session() as session:
            stmt = select(DecentralizedNodeSession).where(
                and_(
                    DecentralizedNodeSession.user_id == uuid.UUID(str(user_id)),
                    DecentralizedNodeSession.revoked.is_(False),
                    DecentralizedNodeSession.expires_at > now,
                )
            )
            result = session.execute(stmt).fetchall()
            return [row[0] for row in result]

    # ActivityPub

    def upsert_activitypub_actor(
        self,
        actor_uri: str,
        preferred_username: str,
        inbox_uri: str,
        outbox_uri: str,
        public_key_pem: str,
        is_local: bool,
        user_id: str | None = None,
        shared_inbox_uri: str | None = None,
        private_key_pem: str | None = None,
    ) -> ActivityPubActor:
        """Upsert activitypub actor."""
        with self.database_session() as session:
            stmt = select(ActivityPubActor).where(ActivityPubActor.actor_uri == actor_uri)
            existing = session.execute(stmt).fetchone()
            actor = existing[0] if existing else None

            if actor is None:
                actor = ActivityPubActor(
                    actor_uri=actor_uri,
                    preferred_username=preferred_username,
                    inbox_uri=inbox_uri,
                    outbox_uri=outbox_uri,
                    shared_inbox_uri=shared_inbox_uri,
                    public_key_pem=public_key_pem,
                    private_key_pem=private_key_pem,
                    is_local=is_local,
                    user_id=uuid.UUID(str(user_id)) if user_id else None,
                    fetched_at=datetime.datetime.now(datetime.timezone.utc)
                    if not is_local
                    else None,
                )
                session.add(actor)
            else:
                actor.preferred_username = preferred_username
                actor.inbox_uri = inbox_uri
                actor.outbox_uri = outbox_uri
                actor.shared_inbox_uri = shared_inbox_uri
                actor.public_key_pem = public_key_pem
                actor.is_local = is_local
                if user_id:
                    actor.user_id = uuid.UUID(str(user_id))
                if private_key_pem:
                    actor.private_key_pem = private_key_pem
                if not is_local:
                    actor.fetched_at = datetime.datetime.now(datetime.timezone.utc)
                session.merge(actor)

            session.commit()
            session.refresh(actor)
            return actor

    def get_activitypub_actor_by_uri(self, actor_uri: str) -> ActivityPubActor | None:
        """Get activitypub actor by uri."""
        with self.database_session() as session:
            stmt = select(ActivityPubActor).where(ActivityPubActor.actor_uri == actor_uri)
            result = session.execute(stmt).fetchone()
            return result[0] if result else None

    def get_activitypub_actor_by_user_id(self, user_id: str) -> ActivityPubActor | None:
        """Get activitypub actor by user id."""
        with self.database_session() as session:
            stmt = select(ActivityPubActor).where(
                ActivityPubActor.user_id == uuid.UUID(str(user_id)),
                ActivityPubActor.is_local.is_(True),
            )
            result = session.execute(stmt).fetchone()
            return result[0] if result else None

    def get_activitypub_actor_by_local_username(
        self, username: str
    ) -> ActivityPubActor | None:
        """Get activitypub actor by local username."""
        with self.database_session() as session:
            stmt = (
                select(ActivityPubActor)
                .join(Users, ActivityPubActor.user_id == Users.user_id)
                .where(
                    Users.username == username,
                    ActivityPubActor.is_local.is_(True),
                )
            )
            result = session.execute(stmt).fetchone()
            return result[0] if result else None

    def create_or_update_activitypub_follow(
        self,
        local_actor_uri: str,
        remote_actor_uri: str,
        follow_activity_uri: str | None = None,
        accepted: bool = False,
    ) -> ActivityPubFollow:
        """Create or update activitypub follow."""
        with self.database_session() as session:
            stmt = select(ActivityPubFollow).where(
                ActivityPubFollow.local_actor_uri == local_actor_uri,
                ActivityPubFollow.remote_actor_uri == remote_actor_uri,
            )
            existing = session.execute(stmt).fetchone()
            follow = existing[0] if existing else None

            if follow is None:
                follow = ActivityPubFollow(
                    local_actor_uri=local_actor_uri,
                    remote_actor_uri=remote_actor_uri,
                    follow_activity_uri=follow_activity_uri,
                    accepted=accepted,
                )
                session.add(follow)
            else:
                follow.accepted = accepted
                if follow_activity_uri:
                    follow.follow_activity_uri = follow_activity_uri
                session.merge(follow)

            session.commit()
            session.refresh(follow)
            return follow

    def accept_activitypub_follow(
        self, local_actor_uri: str, remote_actor_uri: str
    ) -> bool:
        """Accept activitypub follow."""
        with self.database_session() as session:
            stmt = (
                update(ActivityPubFollow)
                .values(accepted=True)
                .where(
                    ActivityPubFollow.local_actor_uri == local_actor_uri,
                    ActivityPubFollow.remote_actor_uri == remote_actor_uri,
                )
            )
            result = session.execute(stmt)
            session.commit()
            return (result.rowcount or 0) > 0

    def list_activitypub_followers(
        self, local_actor_uri: str, accepted_only: bool = True
    ) -> list[ActivityPubFollow]:
        """List activitypub followers."""
        with self.database_session() as session:
            stmt = select(ActivityPubFollow).where(
                ActivityPubFollow.local_actor_uri == local_actor_uri
            )
            if accepted_only:
                stmt = stmt.where(ActivityPubFollow.accepted.is_(True))
            result = session.execute(stmt).fetchall()
            return [row[0] for row in result]

    def list_activitypub_following(self, remote_actor_uri: str) -> list[ActivityPubFollow]:
        """List activitypub following."""
        with self.database_session() as session:
            stmt = select(ActivityPubFollow).where(
                ActivityPubFollow.remote_actor_uri == remote_actor_uri
            )
            result = session.execute(stmt).fetchall()
            return [row[0] for row in result]

    def store_activitypub_inbox_activity(
        self,
        activity_uri: str,
        activity_type: str,
        actor_uri: str,
        payload_json: str,
        target_actor_uri: str | None = None,
    ) -> ActivityPubInboxActivity:
        """Store activitypub inbox activity."""
        with self.database_session() as session:
            existing_stmt = select(ActivityPubInboxActivity).where(
                ActivityPubInboxActivity.activity_uri == activity_uri
            )
            existing = session.execute(existing_stmt).fetchone()
            if existing:
                return existing[0]

            activity = ActivityPubInboxActivity(
                activity_uri=activity_uri,
                activity_type=activity_type,
                actor_uri=actor_uri,
                payload_json=payload_json,
                target_actor_uri=target_actor_uri,
            )
            session.add(activity)
            session.commit()
            session.refresh(activity)
            return activity

    def store_activitypub_outbox_activity(
        self,
        activity_uri: str,
        activity_type: str,
        actor_uri: str,
        payload_json: str,
        object_uri: str | None = None,
    ) -> ActivityPubOutboxActivity:
        """Store activitypub outbox activity."""
        with self.database_session() as session:
            existing_stmt = select(ActivityPubOutboxActivity).where(
                ActivityPubOutboxActivity.activity_uri == activity_uri
            )
            existing = session.execute(existing_stmt).fetchone()
            if existing:
                return existing[0]

            activity = ActivityPubOutboxActivity(
                activity_uri=activity_uri,
                activity_type=activity_type,
                actor_uri=actor_uri,
                payload_json=payload_json,
                object_uri=object_uri,
            )
            session.add(activity)
            session.commit()
            session.refresh(activity)
            return activity

    def get_activitypub_outbox_activities(
        self, actor_uri: str, limit: int = 20, offset: int = 0
    ) -> list[ActivityPubOutboxActivity]:
        """Get activitypub outbox activities."""
        with self.database_session() as session:
            stmt = (
                select(ActivityPubOutboxActivity)
                .where(ActivityPubOutboxActivity.actor_uri == actor_uri)
                .order_by(ActivityPubOutboxActivity.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
            result = session.execute(stmt).fetchall()
            return [row[0] for row in result]

    def update_user_origin_server(self, user_id: str, origin_server: str) -> None:
        """
        Update a user's origin_server.
        """
        with self.database_session() as session:
            stmt = (
                update(Users)
                .values(origin_server=origin_server)
                .where(Users.user_id == uuid.UUID(str(user_id)))
            )
            session.execute(stmt)
            session.commit()

    def list_roles(self) -> list[Roles]:
        """Return all instance roles ordered by creation time."""
        with self.database_session() as session:
            stmt = select(Roles).order_by(Roles.created_at.asc(), Roles.role_name.asc())
            return [row[0] for row in session.execute(stmt).fetchall()]

    def get_role(self, role_id: str) -> Roles | None:
        """Return a role by id."""
        with self.database_session() as session:
            stmt = select(Roles).where(Roles.role_id == role_id)
            row = session.execute(stmt).fetchone()
            return row[0] if row else None

    def role_exists(self, role_id: str) -> bool:
        """Return whether a role exists."""
        return self.get_role(role_id=role_id) is not None

    def list_privileges(self) -> list[Privileges]:
        """Return all known privileges ordered by category then name."""
        with self.database_session() as session:
            stmt = select(Privileges).order_by(
                Privileges.category.asc(), Privileges.privilege_name.asc()
            )
            return [row[0] for row in session.execute(stmt).fetchall()]

    def get_privilege_ids(self) -> set[str]:
        """Return the set of valid privilege ids."""
        with self.database_session() as session:
            stmt = select(Privileges.privilege_id)
            return {row[0] for row in session.execute(stmt).fetchall()}

    def create_role(
        self, role_id: str, role_name: str, privileges_ids: list[str]
    ) -> Roles:
        """Create a custom role."""
        role = Roles(
            role_id=role_id,
            role_name=role_name,
            privileges_ids=sorted(set(privileges_ids)),
        )
        with self.database_session() as session:
            session.add(role)
            session.commit()
            session.refresh(role)
            return role

    def update_role(
        self, role_id: str, *, role_name: str, privileges_ids: list[str]
    ) -> Roles | None:
        """Update an existing role."""
        current_timestamp = datetime.datetime.now(datetime.timezone.utc)
        with self.database_session() as session:
            stmt = select(Roles).where(Roles.role_id == role_id)
            row = session.execute(stmt).fetchone()
            if row is None:
                return None
            role = row[0]
            role.role_name = role_name
            role.privileges_ids = sorted(set(privileges_ids))
            role.updated_at = current_timestamp
            session.add(role)
            session.commit()
            session.refresh(role)
            return role

    def delete_role(self, role_id: str) -> bool:
        """Delete a custom role."""
        with self.database_session() as session:
            stmt = delete(Roles).where(Roles.role_id == role_id)
            result = session.execute(stmt)
            session.commit()
            return bool(result.rowcount)

    def count_users_for_role(self, role_id: str) -> int:
        """Count how many users currently have a role assigned."""
        with self.database_session() as session:
            stmt = select(Users)
            users = [row[0] for row in session.execute(stmt).fetchall()]
            return sum(1 for user in users if role_id in (user.roles_ids or []))

    def update_user_roles(self, user_id: str, role_ids: list[str]) -> Users | None:
        """Replace a user's assigned roles."""
        normalized_role_ids = sorted(set(role_ids or [DEFAULT_ROLE_ID]))
        current_timestamp = datetime.datetime.now(datetime.timezone.utc)
        with self.database_session() as session:
            stmt = select(Users).where(Users.user_id == uuid.UUID(str(user_id)))
            row = session.execute(stmt).fetchone()
            if row is None:
                return None
            user = row[0]
            user.roles_ids = normalized_role_ids
            user.updated_at = current_timestamp
            session.add(user)
            session.commit()
            session.refresh(user)
            return user

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

        return [channel_name[0] for channel_name in channels_names]

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
                channel_name=channel.channel_name,
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
            stmt = select(Channels).where(Channels.channel_id == channel_id)

            channel_metadata = session.execute(stmt).fetchone()

        if channel_metadata is not None:
            channel_metadata = channel_metadata[0]

        return channel_metadata

    def get_first_public_channel(self) -> Channels | None:
        """Get first public channel."""
        with self.database_session() as session:
            stmt = (
                select(Channels)
                .where(Channels.is_private.is_(False))
                .order_by(Channels.created_at.asc())
                .limit(1)
            )
            result = session.execute(stmt).fetchone()
            return result[0] if result else None

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
            stmt = delete(Channels).where(Channels.channel_id == channel_id)

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
        database_uri = str(self.database_engine.url)
        with self.database_session() as session:
            if database_uri.startswith("sqlite://"):
                stmt = select(Channels).where(Channels.channel_id == channel_id)
                row = session.execute(stmt).fetchone()
                if row is None:
                    return
                channel = row[0]
                allowed_users = list(channel.allowed_users or [])
                if to_add_user_id not in allowed_users:
                    allowed_users.append(to_add_user_id)
                channel.allowed_users = allowed_users
                session.add(channel)
            else:
                stmt = (
                    update(Channels)
                    .values(
                        allowed_users=text(
                            "array_append(allowed_users, '%s')" % to_add_user_id
                        )
                    )
                    .where(Channels.channel_id == channel_id)
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
        database_uri = str(self.database_engine.url)
        with self.database_session() as session:
            if database_uri.startswith("sqlite://"):
                stmt = select(Channels).where(Channels.channel_id == channel_id)
                row = session.execute(stmt).fetchone()
                if row is None:
                    return
                channel = row[0]
                channel.allowed_users = [
                    user_id
                    for user_id in (channel.allowed_users or [])
                    if user_id != to_remove_user_id
                ]
                session.add(channel)
            else:
                stmt = (
                    update(Channels)
                    .values(
                        allowed_users=text(
                            "array_remove(allowed_users, '%s')" % to_remove_user_id
                        )
                    )
                    .where(Channels.channel_id == channel_id)
                )
                session.execute(stmt)

            session.commit()

    def fetch_channel_messages(
        self, channel_id: str, messages_per_page: int, page: int
    ) -> list[tuple[Messages, Users | None]]:
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

            start_index = (page * messages_per_page) - messages_per_page

            response = (
                session.query(Messages, Users)
                .join(Users, Messages.sender_id == Users.user_id, isouter=True)
                .filter(Messages.message_id.in_(channel_messages_ids))
                .order_by(Messages.sent_at)
                .offset(start_index)
                .limit(messages_per_page)
                .all()
            )

            messages_with_users = response

        return messages_with_users

    def fetch_unviewed_channel_messages(
        self, channel_id: str, viewed_messages_ids: list[str]
    ) -> list[tuple[Messages, Users | None]]:
        """
        Fetch latest unviewed messages by this user from a server channel

        Args:
            user_id (str): The user's `user_id`.
            channel_id (str): The channel's `channel_id`.
            viewed_messages_ids (list[str]): A list of viewed `message_id`s by this user.

        Returns:
            list[Messages]: A list of `Messages` table object.
        """
        messages_with_users: list[tuple[Messages, Users | None]] = []

        with self.database_session() as session:
            query = (
                session.query(Messages, Users)
                .join(Users, Messages.sender_id == Users.user_id, isouter=True)
                .filter(Messages.channel_id == channel_id)
            )

            if viewed_messages_ids:
                query = query.filter(Messages.message_id.not_in(viewed_messages_ids))

            messages_with_users = query.order_by(Messages.sent_at).all()

        return messages_with_users

    def fetch_conversation_messages(
        self, conversation_id: str, messages_per_page: int, page: int
    ) -> list[tuple[Messages, Users | None]]:
        """
        Fetch a specific number of direct messages for a conversation_id.
        """
        messages_with_users: list[tuple[Messages, Users | None]] = []
        start_index = (page * messages_per_page) - messages_per_page

        with self.database_session() as session:
            response = (
                session.query(Messages, Users)
                .join(Users, Messages.sender_id == Users.user_id, isouter=True)
                .filter(Messages.conversation_id == conversation_id)
                .order_by(Messages.sent_at)
                .offset(start_index)
                .limit(messages_per_page)
                .all()
            )
            messages_with_users = response

        return messages_with_users

    def update_channel_participants(
        self, channel_id: str, participant_ids: list[str]
    ) -> None:
        """
        Update active voice participants for a channel.
        """
        with self.database_session() as session:
            stmt = (
                update(Channels)
                .values(participant_ids=participant_ids)
                .where(Channels.channel_id == channel_id)
            )
            session.execute(stmt)
            session.commit()

    def save_message(self, message: Messages) -> None:
        """
        Save a message to the `messages` table in the database

        Args:
            message(Messages): A `Messages` table object.

        Returns:
            None
        """
        database_uri = str(self.database_engine.url)
        is_sqlite = database_uri.startswith("sqlite://")

        with self.database_session() as session:
            if isinstance(message.sent_at, str):
                try:
                    normalized_sent_at = message.sent_at.replace("Z", "+00:00")
                    message.sent_at = datetime.datetime.fromisoformat(normalized_sent_at)
                except ValueError:
                    message.sent_at = datetime.datetime.now(datetime.timezone.utc)

            if is_sqlite:
                channel = session.get(Channels, message.channel_id)
                if channel is not None:
                    messages_ids = list(channel.messages_ids or [])
                    if message.message_id not in messages_ids:
                        messages_ids.append(message.message_id)
                    channel.messages_ids = messages_ids
                    session.add(channel)
            else:
                stmt = (
                    update(Channels)
                    .values(
                        messages_ids=text(
                            "array_append(messages_ids, '%s')" % message.message_id
                        )
                    )
                    .where(Channels.channel_id == message.channel_id)
                )
                session.execute(stmt)
            session.add(message)

            session.commit()

    def save_direct_message(self, message: Messages) -> None:
        """
        Save a direct message with no channel linkage.
        """
        with self.database_session() as session:
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
            stmt = select(Messages).where(Messages.message_id == message_id)

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
        updated_at = datetime.datetime.now(datetime.timezone.utc)
        read_history_user_id = str(user_id) if self._is_sqlite() else user_id

        with self.database_session() as session:
            stmt = select(MessageReadHistory).where(
                MessageReadHistory.user_id == read_history_user_id
            )
            read_history = session.execute(stmt).scalar_one_or_none()

            if read_history is None:
                read_history = MessageReadHistory(
                    user_id=read_history_user_id,
                    viewed_messages_ids=[message_id],
                    updated_at=updated_at,
                )
                session.add(read_history)
                session.commit()
                return

            current_ids = list(read_history.viewed_messages_ids or [])
            if message_id not in current_ids:
                current_ids.append(message_id)
                read_history.viewed_messages_ids = current_ids

            read_history.updated_at = updated_at

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
                update(Channels)
                .where(Channels.channel_id == channel_id)
                .values(
                    messages_ids=text("array_remove(messages_ids, '%s')" % message_id)
                ),
                delete(Messages).where(Messages.message_id == message_id),
                delete(Keys).where(Keys.message_id == message_id),
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
                blocked_ips.append(
                    {
                        "ip": blocked_ip.ip,
                        "reason": blocked_ip.block_reason,
                        "blocked_at": blocked_ip.blocked_at.isoformat(),
                    }
                )

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

    def delete_blocked_ip(
        self, blocked_ip: BlockedIPS | None = None, ip: str | None = None
    ) -> bool:
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
                result = session.execute(
                    delete(BlockedIPS).where(BlockedIPS.ip == blocked_ip.ip)
                )
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
        if database_uri.startswith("sqlite://"):
            return

        with self.database_session() as session:
            session.add(server)
            session.commit()

    def update_server_values(
        self,
        server_name: str,
        server_welcome_message: str,
        description: str | None = None,
    ) -> None:
        """
        Updates the server's info.
        """
        updated_at = date_in_gmt()

        with self.database_session() as session:
            stmt = update(Server).values(
                server_name=server_name,
                welcome_message=server_welcome_message,
                description=description,
                updated_at=updated_at,
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
        if database_uri.startswith("sqlite://"):
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
            stmt = update(Server).values(members_count=current_members_count + n)

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
        if database_uri.startswith("sqlite://"):
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
        if database_uri.startswith("sqlite://"):
            return

        if not settings_updates:
            return

        updated_at = date_in_gmt()

        with self.database_session() as session:
            stmt = update(ServerSettings).values(
                updated_at=updated_at, **settings_updates
            )

            session.execute(stmt)
            session.commit()

        logger.info(f"Server settings updated: {list(settings_updates.keys())}")

    def initialize_default_roles_and_privileges(self) -> None:
        """
        Initialize the built-in role and privilege catalog.

        Args:
            None.

        Returns:
            None.
        """
        # Default privileges data
        default_privileges = [
            # User Management
            {
                "id": "create_users",
                "name": "Create Users",
                "category": "user_management",
            },
            {
                "id": "delete_users",
                "name": "Delete Users",
                "category": "user_management",
            },
            {"id": "edit_users", "name": "Edit Users", "category": "user_management"},
            {"id": "view_users", "name": "View Users", "category": "user_management"},
            {
                "id": "reset_user_tokens",
                "name": "Reset User Tokens",
                "category": "user_management",
            },
            # Channel Management
            {
                "id": "create_channels",
                "name": "Create Channels",
                "category": "channel_management",
            },
            {
                "id": "delete_channels",
                "name": "Delete Channels",
                "category": "channel_management",
            },
            {
                "id": "edit_channels",
                "name": "Edit Channels",
                "category": "channel_management",
            },
            {
                "id": "manage_channel_users",
                "name": "Manage Channel Users",
                "category": "channel_management",
            },
            {
                "id": "view_private_channels",
                "name": "View Private Channels",
                "category": "channel_management",
            },
            # Message Management
            {
                "id": "send_messages",
                "name": "Send Messages",
                "category": "message_management",
            },
            {
                "id": "delete_messages",
                "name": "Delete Messages",
                "category": "message_management",
            },
            {
                "id": "edit_messages",
                "name": "Edit Messages",
                "category": "message_management",
            },
            {
                "id": "view_messages",
                "name": "View Messages",
                "category": "message_management",
            },
            # Server Management
            {
                "id": "manage_server_settings",
                "name": "Manage Server Settings",
                "category": "server_management",
            },
            {
                "id": "manage_server_privileges",
                "name": "Manage Server Privileges",
                "category": "server_management",
            },
            {"id": "manage_cdn", "name": "Manage Storage", "category": "server_management"},
            {
                "id": "view_server_stats",
                "name": "View Server Stats",
                "category": "server_management",
            },
            # Moderation
            {"id": "ban_users", "name": "Ban Users", "category": "moderation"},
            {"id": "mute_users", "name": "Mute Users", "category": "moderation"},
            {
                "id": "moderate_content",
                "name": "Moderate Content",
                "category": "moderation",
            },
            {
                "id": "view_audit_logs",
                "name": "View Audit Logs",
                "category": "moderation",
            },
            {
                "id": "manage_blocked_ips",
                "name": "Manage Blocked IPs",
                "category": "moderation",
            },
            # Storage Management
            {
                "id": "upload_files",
                "name": "Upload Files",
                "category": "storage_management",
            },
            {
                "id": "delete_files",
                "name": "Delete Files",
                "category": "storage_management",
            },
            {"id": "view_files", "name": "View Files", "category": "storage_management"},
            {
                "id": "manage_background_tasks",
                "name": "Manage Background Tasks",
                "category": "server_management",
            },
        ]

        # Default roles data
        default_roles = [
            {
                "id": "owner",
                "name": "Server Owner",
                "privileges": [
                    # All privileges for owner
                    "create_users",
                    "delete_users",
                    "edit_users",
                    "view_users",
                    "reset_user_tokens",
                    "create_channels",
                    "delete_channels",
                    "edit_channels",
                    "manage_channel_users",
                    "view_private_channels",
                    "send_messages",
                    "delete_messages",
                    "edit_messages",
                    "view_messages",
                    "manage_server_settings",
                    "manage_server_privileges",
                    "manage_cdn",
                    "view_server_stats",
                    "ban_users",
                    "mute_users",
                    "moderate_content",
                    "view_audit_logs",
                    "manage_blocked_ips",
                    "upload_files",
                    "delete_files",
                    "view_files",
                    "manage_background_tasks",
                ],
            },
            {
                "id": "admin",
                "name": "Administrator",
                "privileges": [
                    # Most privileges except server owner specific ones
                    "create_users",
                    "edit_users",
                    "view_users",
                    "reset_user_tokens",
                    "create_channels",
                    "delete_channels",
                    "edit_channels",
                    "manage_channel_users",
                    "view_private_channels",
                    "send_messages",
                    "delete_messages",
                    "edit_messages",
                    "view_messages",
                    "manage_server_settings",
                    "view_server_stats",
                    "ban_users",
                    "mute_users",
                    "moderate_content",
                    "view_audit_logs",
                    "manage_blocked_ips",
                    "upload_files",
                    "delete_files",
                    "view_files",
                    "manage_background_tasks",
                ],
            },
            {
                "id": "moderator",
                "name": "Moderator",
                "privileges": [
                    # Moderation and basic management
                    "view_users",
                    "create_channels",
                    "edit_channels",
                    "manage_channel_users",
                    "send_messages",
                    "delete_messages",
                    "edit_messages",
                    "view_messages",
                    "view_private_channels",
                    "ban_users",
                    "mute_users",
                    "moderate_content",
                    "upload_files",
                    "view_files",
                ],
            },
            {
                "id": "user",
                "name": "Regular User",
                "privileges": [
                    # Basic user privileges
                    "send_messages",
                    "view_messages",
                    "upload_files",
                    "view_files",
                    "view_users",
                ],
            },
        ]

        with self.database_session() as session:
            existing_privileges_count = session.query(Privileges).count()
            existing_roles_count = session.query(Roles).count()

            if existing_privileges_count > 0 or existing_roles_count > 0:
                logger.info(
                    "Default roles/privileges already exist, skipping initialization"
                )
                return

            for privilege_data in default_privileges:
                privilege = Privileges(
                    privilege_id=privilege_data["id"],
                    privilege_name=privilege_data["name"],
                    category=privilege_data["category"],
                )
                session.add(privilege)

            # Add all roles
            for role_data in default_roles:
                role = Roles(
                    role_id=role_data["id"],
                    role_name=role_data["name"],
                    privileges_ids=role_data["privileges"],
                )
                session.add(role)

            session.commit()
            logger.info("Default roles and privileges initialized successfully")

    def initialize_default_server_settings(self) -> None:
        """Initialize default server settings when the table exists."""
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return

        with self.database_session() as session:
            existing_server_settings_count = session.query(ServerSettings).count()
            if existing_server_settings_count > 0:
                logger.info("Default server settings already exist, skipping initialization")
                return

            server_settings = ServerSettings(
                server_settings_id="global_settings",
                is_private=False,
                max_message_length=50000,
                max_image_size=5,
                max_video_size=50,
                max_sticker_size=5,
                max_gif_size=10,
                allowed_images_extensions=["png", "jpg", "jpeg", "gif", "webp"],
                allowed_stickers_extensions=["png", "gif"],
                allowed_gif_extensions=["gif"],
                allowed_videos_extensions=["mp4", "webm"],
                allowed_doc_extensions=["pdf", "doc", "docx", "txt", "zip"],
                rate_limit_duration=5,
                max_rate_limit_requests=6000,
                max_rate_limit_warnings=15,
            )
            session.add(server_settings)
            session.commit()
            logger.info("Default server settings initialized successfully")

    def initialize_default_data(self) -> None:
        """
        Initializes default roles, privileges, and server settings.
        Idempotent - safe to run multiple times without errors.
        """
        self.initialize_default_roles_and_privileges()
        self.initialize_default_server_settings()

    def is_system_role(self, role_id: str) -> bool:
        """Return whether a role id is reserved by the instance."""
        return role_id in IMMUTABLE_ROLE_IDS


    def add_sticker_to_catalog(
        self, sticker_url: str, filename: str, uploaded_by: uuid.UUID
    ) -> str:
        """
        Add a sticker to the server catalog if it doesn't already exist.

        Args:
            sticker_url (str): The storage URL of the sticker
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
            uploaded_by=uploaded_by,
        )

        with self.database_session() as session:
            session.add(sticker)
            session.commit()

        return sticker_id

    def add_gif_to_catalog(
        self, gif_url: str, filename: str, uploaded_by: uuid.UUID
    ) -> str:
        """
        Add a GIF to the server catalog if it doesn't already exist.

        Args:
            gif_url (str): The storage URL of the GIF
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
            gif_id=gif_id, gif_url=gif_url, filename=filename, uploaded_by=uploaded_by
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
            stmt = select(ServerStickers).where(
                ServerStickers.sticker_url == sticker_url
            )
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
            stmt = (
                update(ServerStickers)
                .values(
                    usage_count=ServerStickers.usage_count + 1,
                    updated_at=datetime.datetime.now(datetime.timezone.utc),
                )
                .where(ServerStickers.sticker_id == sticker_id)
            )
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
            stmt = (
                update(ServerGIFs)
                .values(
                    usage_count=ServerGIFs.usage_count + 1,
                    updated_at=datetime.datetime.now(datetime.timezone.utc),
                )
                .where(ServerGIFs.gif_id == gif_id)
            )
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
            stmt = (
                select(ServerStickers)
                .where(ServerStickers.is_active == True)
                .order_by(
                    ServerStickers.usage_count.desc(), ServerStickers.created_at.desc()
                )
                .limit(limit)
                .offset(offset)
            )

            stickers = session.execute(stmt).fetchall()

            return [
                {
                    "sticker_id": s.sticker_id,
                    "sticker_url": s.sticker_url,
                    "filename": s.filename,
                    "uploaded_by": str(s.uploaded_by),
                    "usage_count": s.usage_count,
                    "created_at": s.created_at,
                    "updated_at": s.updated_at,
                }
                for s in stickers
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
            stmt = (
                select(ServerGIFs)
                .where(ServerGIFs.is_active == True)
                .order_by(ServerGIFs.usage_count.desc(), ServerGIFs.created_at.desc())
                .limit(limit)
                .offset(offset)
            )

            gifs = session.execute(stmt).fetchall()

            return [
                {
                    "gif_id": g.gif_id,
                    "gif_url": g.gif_url,
                    "filename": g.filename,
                    "uploaded_by": str(g.uploaded_by),
                    "usage_count": g.usage_count,
                    "created_at": g.created_at,
                    "updated_at": g.updated_at,
                }
                for g in gifs
            ]

    # Chart Data Methods for Background Tasks

