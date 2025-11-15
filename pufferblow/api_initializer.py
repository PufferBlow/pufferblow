from loguru import logger

# Authentification token manager
from pufferblow.api.auth.auth_token_manager import AuthTokenManager

# Channels manager
from pufferblow.api.channels.channels_manager import ChannelsManager

# Config handler
from pufferblow.api.config.config_handler import ConfigHandler

# Database
from pufferblow.api.database.database import Database
from pufferblow.api.database.database_handler import DatabaseHandler

# Encryption/Decryption manager
from pufferblow.api.hasher.hasher import Hasher

# Messages manager
from pufferblow.api.messages.messages_manager import MessagesManager

# Server manager
from pufferblow.api.server.server_manager import ServerManager

# Users manager
from pufferblow.api.user.user_manager import UserManager

# WebSockets manager
from pufferblow.api.websocket.websocket_manager import WebSocketsManager

# CDN manager - conditionally imported
try:
    from pufferblow.api.storage.storage_manager import StorageManager

    STORAGE_AVAILABLE = True
except ImportError:
    CDN_AVAILABLE = False
    CDNManager = None

# Background tasks manager
from pufferblow.api.background_tasks import BackgroundTasksManager

# Log messages
from pufferblow.api.logger.msgs import errors

# Models
from pufferblow.api.models.config_model import Config

# SecurityChecks handler
from pufferblow.api.security.security_checks_handler import SecurityChecksHandler

# WebRTC manager
from pufferblow.api.webrtc.webrtc_manager import initialize_webrtc_manager


class APIInitializer:
    """
    Api initializer class handles the start up of all the needed object
    that will be used by the PufferBlow's API

    Attributes:
        config                (Config)              : A `Config` object.
        hasher                (Hasher)              : A `Hasher` object.
        database              (Database)            : A `Database` object.
        database_handler      (DatabaseHandler)     : A `DatabaseHandler` object.
        auth_token_manager    (AuthTokenManager)    : A `AuthTokenManager` object.
        user_manager          (UserManager)         : A `UserManger` object.
        channels_manager      (ChannelsManager)     : A `ChannelsManager` object.
    """

    config: Config = None
    hasher: Hasher = None
    database: Database = None
    database_handler: DatabaseHandler = None
    server_manager: ServerManager = None
    auth_token_manager: AuthTokenManager = None
    user_manager: UserManager = None
    channels_manager: ChannelsManager = None
    websockets_manager: WebSocketsManager = None
    storage_manager: StorageManager = None
    background_tasks_manager: BackgroundTasksManager = None
    security_checks_handler: SecurityChecksHandler = None

    is_loaded: bool = False

    def __init__(self) -> None:
        pass

    def load_objects(self, database_uri: str | None = None) -> None:
        """
        Load all the objects that will be used by the API

        Args:
            `None`.

        Returns:
            `None`.
        """
        if self.is_loaded:
            return

        # Init config
        self.load_config()

        # Init the hasher
        self.hasher = Hasher()

        # Init Database
        self.load_database(database_uri=database_uri)

        # Initialize default roles, privileges, and server settings for PostgreSQL databases
        # This ensures they're always present when the system starts
        database_uri_check = str(self.database_handler.database_engine.url)
        if not database_uri_check.startswith("sqlite://"):
            self.database_handler.initialize_default_data()

        # Server manager
        self.server_manager = ServerManager(database_handler=self.database_handler)

        # Init Auth tokens manager
        self.auth_token_manager = AuthTokenManager(
            database_handler=self.database_handler, hasher=self.hasher
        )

        # Init user manager
        self.user_manager = UserManager(
            database_handler=self.database_handler,
            auth_token_manager=self.auth_token_manager,
            hasher=self.hasher,
            config=self.config,
        )

        # Init channels manager
        self.channels_manager = ChannelsManager(
            database_handler=self.database_handler,
            auth_token_manager=self.auth_token_manager,
            hasher=self.hasher,
        )

        # Init messages manager
        self.messages_manager = MessagesManager(
            database_handler=self.database_handler,
            auth_token_manager=self.auth_token_manager,
            user_manager=self.user_manager,
            hasher=self.hasher,
        )

        # Init websockets manager
        self.websockets_manager = WebSocketsManager()

        # Init storage manager (only if available)
        if STORAGE_AVAILABLE and StorageManager:
            # Create storage config from main config
            storage_config = {
                "provider": self.config.STORAGE_PROVIDER,
                "storage_path": self.config.STORAGE_PATH,
                "base_url": self.config.STORAGE_BASE_URL,
                "allocated_space_gb": self.config.STORAGE_ALLOCATED_GB,
                "api_host": self.config.API_HOST,
                "api_port": self.config.API_PORT,
                "bucket_name": self.config.S3_BUCKET_NAME,
                "region": self.config.S3_REGION,
                "access_key": self.config.S3_ACCESS_KEY,
                "secret_key": self.config.S3_SECRET_KEY,
                "endpoint_url": self.config.S3_ENDPOINT_URL,
            }

            self.storage_manager = StorageManager(
                storage_config=storage_config, database_handler=self.database_handler
            )
            # Update storage limits from server settings
            self.storage_manager.update_server_limits()
        else:
            self.storage_manager = None
            logger.warning(
                "Storage manager not available - file upload features will be disabled"
            )

        # Init background tasks manager (only register, don't start scheduler)
        self.background_tasks_manager = BackgroundTasksManager(
            database_handler=self.database_handler,
            storage_manager=self.storage_manager,
            config=self.config,
        )

        # Register background tasks (but don't start the scheduler in CLI)
        import sys

        is_cli = len(sys.argv) > 1 and sys.argv[1] in ["version", "setup", "serve"]
        if not is_cli or (is_cli and len(sys.argv) > 1 and sys.argv[1] == "serve"):
            # Only register/start background tasks in server mode
            self._register_background_tasks()

        # Init security checks handlker
        self.security_checks_handler = SecurityChecksHandler(
            database_handler=self.database_handler,
            user_manager=self.user_manager,
            channels_manager=self.channels_manager,
            auth_token_manager=self.auth_token_manager,
        )

        # Init WebRTC manager
        initialize_webrtc_manager(self.database_handler)

        self.is_loaded = True

    def _register_background_tasks(self) -> None:
        """
        Register background tasks that will be scheduled to run periodically.
        """
        # Register storage cleanup task - run every 24 hours
        self.background_tasks_manager.register_task(
            task_id="storage_cleanup",
            task_func=self.background_tasks_manager.cleanup_storage_orphaned_files,
            interval_hours=24,
            enabled=True,
        )

        # Register auth token cleanup task - run every 12 hours
        self.background_tasks_manager.register_task(
            task_id="auth_token_cleanup",
            task_func=self.background_tasks_manager.cleanup_expired_auth_tokens,
            interval_hours=12,
            enabled=True,
        )

        # Register server statistics update task - run every 15 minutes
        self.background_tasks_manager.register_task(
            task_id="server_stats_update",
            task_func=self.background_tasks_manager.update_server_statistics,
            interval_minutes=15,
            enabled=True,
        )

        # Register chart data update task - run every hour
        self.background_tasks_manager.register_task(
            task_id="chart_data_update",
            task_func=self.background_tasks_manager.update_chart_data,
            interval_hours=1,
            enabled=True,
        )

        # Register GitHub releases check task - run every 6 hours
        self.background_tasks_manager.register_task(
            task_id="github_releases_check",
            task_func=self.background_tasks_manager.check_github_releases,
            interval_hours=6,
            enabled=True,
        )

        # Register activity metrics update task - run every 6 hours
        self.background_tasks_manager.register_task(
            task_id="activity_metrics_update",
            task_func=self.background_tasks_manager.update_activity_metrics,
            interval_hours=6,
            enabled=True,
        )

    def load_database(self, database_uri: str | None = None) -> None:
        """
        Load the database and the database handler.
        """
        if self.config is None and database_uri is None:
            self.load_config()

        if database_uri is not None:
            self.database = Database(database_uri=database_uri)
        else:
            self.database = Database(config=self.config)

        database_engine = self.database.create_database_engine_instance()

        self.database_handler = DatabaseHandler(
            database_engine=database_engine, hasher=self.hasher, config=self.config
        )

    def load_config(self) -> None:
        """
        Load the config handler and the config model.
        """
        self.config_handler = ConfigHandler()

        if not self.config_handler.check_config():
            # During setup, missing config is expected - don't log error
            import sys

            if len(sys.argv) > 1 and "setup" in sys.argv:
                pass  # Silently skip error during setup
            else:
                logger.error(
                    errors.ERROR_NO_CONFIG_FILE_FOUND(
                        self.config_handler.config_file_path
                    )
                )
            # sys.exit(1)

        try:
            config = self.config_handler.load_config()
            if len(config) == 0:
                self.config = Config()
            else:
                self.config = Config(config=config)
        except FileNotFoundError:
            # Config might not exist during setup - create empty config
            import sys

            if len(sys.argv) > 1 and "setup" in sys.argv:
                self.config = Config()  # Use defaults during setup
            else:
                logger.error("Configuration file not found and not in setup mode")
                raise


# PufferBlow's APIs objects loader
api_initializer: APIInitializer = APIInitializer()
