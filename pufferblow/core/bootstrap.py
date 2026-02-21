"""Application bootstrap and shared object wiring for API and CLI runtimes."""

import sys

from loguru import logger

from pufferblow.api.activitypub import ActivityPubManager
from pufferblow.api.auth.auth_token_manager import AuthTokenManager
from pufferblow.api.auth.decentralized_auth_manager import DecentralizedAuthManager
from pufferblow.api.background_tasks import BackgroundTasksManager
from pufferblow.api.channels.channels_manager import ChannelsManager
from pufferblow.api.config.config_handler import ConfigHandler
from pufferblow.api.database.database import Database
from pufferblow.api.database.database_handler import DatabaseHandler
from pufferblow.api.hasher.hasher import Hasher
from pufferblow.api.logger.msgs import errors
from pufferblow.api.messages.messages_manager import MessagesManager
from pufferblow.api.models.config_model import Config
from pufferblow.api.security.security_checks_handler import SecurityChecksHandler
from pufferblow.api.server.server_manager import ServerManager
from pufferblow.api.user.user_manager import UserManager
from pufferblow.api.webrtc.webrtc_manager import initialize_webrtc_manager
from pufferblow.api.websocket.websocket_manager import WebSocketsManager

try:
    from pufferblow.api.storage.storage_manager import StorageManager

    STORAGE_AVAILABLE = True
except ImportError:
    STORAGE_AVAILABLE = False
    StorageManager = None


class APIInitializer:
    """
    Lazily initializes and shares API managers used across the application.

    The initializer is intentionally stateful and exposed as a singleton
    (`api_initializer`) so routes and managers share one runtime container.
    """

    config: Config = None
    hasher: Hasher = None
    database: Database = None
    database_handler: DatabaseHandler = None
    server_manager: ServerManager = None
    auth_token_manager: AuthTokenManager = None
    user_manager: UserManager = None
    channels_manager: ChannelsManager = None
    messages_manager: MessagesManager = None
    websockets_manager: WebSocketsManager = None
    storage_manager: StorageManager = None
    background_tasks_manager: BackgroundTasksManager = None
    security_checks_handler: SecurityChecksHandler = None
    decentralized_auth_manager: DecentralizedAuthManager = None
    activitypub_manager: ActivityPubManager = None
    config_handler: ConfigHandler = None

    is_loaded: bool = False

    def __init__(self) -> None:
        """Initialize the instance."""
        pass

    @staticmethod
    def _is_cli_setup_mode() -> bool:
        """Return whether the process is currently executing CLI setup flow."""
        return len(sys.argv) > 1 and "setup" in sys.argv

    def load_objects(self, database_uri: str | None = None) -> None:
        """
        Initialize shared managers and handlers when they are not loaded yet.

        Args:
            database_uri: Optional database URI override, mainly used by setup.
        """
        if self.is_loaded:
            return

        self.load_config()
        self.hasher = Hasher()
        self.load_database(database_uri=database_uri)

        database_uri_check = str(self.database_handler.database_engine.url)
        if not database_uri_check.startswith("sqlite://"):
            self.database_handler.initialize_default_data()

        self.server_manager = ServerManager(database_handler=self.database_handler)
        self.auth_token_manager = AuthTokenManager(
            database_handler=self.database_handler, hasher=self.hasher
        )
        self.user_manager = UserManager(
            database_handler=self.database_handler,
            auth_token_manager=self.auth_token_manager,
            hasher=self.hasher,
            config=self.config,
        )
        self.channels_manager = ChannelsManager(
            database_handler=self.database_handler,
            auth_token_manager=self.auth_token_manager,
            hasher=self.hasher,
        )
        self.messages_manager = MessagesManager(
            database_handler=self.database_handler,
            auth_token_manager=self.auth_token_manager,
            user_manager=self.user_manager,
            hasher=self.hasher,
        )
        self.websockets_manager = WebSocketsManager(user_manager=self.user_manager)

        if STORAGE_AVAILABLE and StorageManager:
            storage_config = {
                "provider": self.config.STORAGE_PROVIDER,
                "storage_path": self.config.STORAGE_PATH,
                "base_url": self.config.STORAGE_BASE_URL,
                "allocated_space_gb": self.config.STORAGE_ALLOCATED_GB,
                "api_host": self.config.API_HOST,
                "api_port": self.config.API_PORT,
                "sse_enabled": self.config.STORAGE_SSE_ENABLED,
                "sse_key": self.config.STORAGE_SSE_KEY,
                "bucket_name": self.config.S3_BUCKET_NAME,
                "region": self.config.S3_REGION,
                "access_key": self.config.S3_ACCESS_KEY,
                "secret_key": self.config.S3_SECRET_KEY,
                "endpoint_url": self.config.S3_ENDPOINT_URL,
            }
            self.storage_manager = StorageManager(
                storage_config=storage_config,
                database_handler=self.database_handler,
            )
            self.storage_manager.update_server_limits()
        else:
            self.storage_manager = None
            logger.warning(
                "Storage manager not available - file upload features are disabled."
            )

        self.background_tasks_manager = BackgroundTasksManager(
            database_handler=self.database_handler,
            storage_manager=self.storage_manager,
            config=self.config,
        )

        is_cli = len(sys.argv) > 1 and sys.argv[1] in ["version", "setup", "serve"]
        if not is_cli or (is_cli and len(sys.argv) > 1 and sys.argv[1] == "serve"):
            self._register_background_tasks()

        self.security_checks_handler = SecurityChecksHandler(
            database_handler=self.database_handler,
            user_manager=self.user_manager,
            channels_manager=self.channels_manager,
            auth_token_manager=self.auth_token_manager,
        )
        self.decentralized_auth_manager = DecentralizedAuthManager(
            database_handler=self.database_handler
        )
        self.activitypub_manager = ActivityPubManager(
            database_handler=self.database_handler,
            user_manager=self.user_manager,
            messages_manager=self.messages_manager,
            websockets_manager=self.websockets_manager,
        )
        initialize_webrtc_manager(self.database_handler)

        self.is_loaded = True

    def _register_background_tasks(self) -> None:
        """Register periodic background tasks for scheduler startup."""
        self.background_tasks_manager.register_task(
            task_id="storage_cleanup",
            task_func=self.background_tasks_manager.cleanup_storage_orphaned_files,
            interval_hours=24,
            enabled=True,
        )
        self.background_tasks_manager.register_task(
            task_id="auth_token_cleanup",
            task_func=self.background_tasks_manager.cleanup_expired_auth_tokens,
            interval_hours=12,
            enabled=True,
        )
        self.background_tasks_manager.register_task(
            task_id="server_stats_update",
            task_func=self.background_tasks_manager.update_server_statistics,
            interval_minutes=15,
            enabled=True,
        )
        self.background_tasks_manager.register_task(
            task_id="chart_data_update",
            task_func=self.background_tasks_manager.update_chart_data,
            interval_hours=1,
            enabled=True,
        )
        self.background_tasks_manager.register_task(
            task_id="github_releases_check",
            task_func=self.background_tasks_manager.check_github_releases,
            interval_hours=6,
            enabled=True,
        )
        self.background_tasks_manager.register_task(
            task_id="activity_metrics_update",
            task_func=self.background_tasks_manager.update_activity_metrics,
            interval_hours=6,
            enabled=True,
        )

    def load_database(self, database_uri: str | None = None) -> None:
        """
        Initialize database and database handler.

        Args:
            database_uri: Optional database URI override.
        """
        if self.config is None and database_uri is None:
            self.load_config()

        if database_uri is not None:
            self.database = Database(database_uri=database_uri)
        else:
            self.database = Database(config=self.config)

        database_engine = self.database.create_database_engine_instance()
        self.database_handler = DatabaseHandler(
            database_engine=database_engine,
            hasher=self.hasher,
            config=self.config,
        )

    def load_config(self) -> None:
        """Load configuration from disk into a `Config` model instance."""
        self.config_handler = ConfigHandler()

        if not self.config_handler.check_config():
            if not self._is_cli_setup_mode():
                logger.error(
                    errors.ERROR_NO_CONFIG_FILE_FOUND(
                        self.config_handler.config_file_path
                    )
                )

        try:
            config = self.config_handler.load_config()
            self.config = Config() if len(config) == 0 else Config(config=config)
        except FileNotFoundError:
            if self._is_cli_setup_mode():
                self.config = Config()
            else:
                logger.error("Configuration file not found and not in setup mode.")
                raise


api_initializer: APIInitializer = APIInitializer()
