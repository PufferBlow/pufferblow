from loguru import logger

# Encryption/Decryption manager
from pufferblow.api.hasher.hasher import Hasher

# Config handler
from pufferblow.api.config.config_handler import ConfigHandler

# Users manager
from pufferblow.api.user.user_manager import UserManager

# Authentification token manager
from pufferblow.api.auth.auth_token_manager import AuthTokenManager

# Database
from pufferblow.api.database.database import Database
from pufferblow.api.database.database_handler import DatabaseHandler

# Server manager
from pufferblow.api.server.server_manager import ServerManager

# Channels manager
from pufferblow.api.channels.channels_manager import ChannelsManager

# Messages manager
from pufferblow.api.messages.messages_manager import MessagesManager

# WebSockets manager
from pufferblow.api.websocket.websocket_manager import WebSocketsManager

# SecurityChecks handler
from pufferblow.api.security.security_checks_handler import SecurityChecksHandler

# Models
from pufferblow.api.models.config_model import Config 

# Log messages
from pufferblow.api.logger.msgs import (
    errors    
)

class APIInitializer(object):
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
        Channels_manager      (ChannelsManager)     : A `ChannelsManager` object.
    """
    config                  :       Config                  =   None
    hasher                  :       Hasher                  =   None
    database                :       Database                =   None
    database_handler        :       DatabaseHandler         =   None
    server_manager          :       ServerManager           =   None
    auth_token_manager      :       AuthTokenManager        =   None
    user_manager            :       UserManager             =   None
    channels_manager        :       ChannelsManager         =   None
    websockets_manager      :       WebSocketsManager       =   None
    security_checks_handler :       SecurityChecksHandler   =   None

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
        
        # Server manager
        self.server_manager = ServerManager(
            database_handler=self.database_handler
        )

        # Init Auth tokens manager
        self.auth_token_manager = AuthTokenManager(
            database_handler        =       self.database_handler,
            hasher                  =       self.hasher
        )

        # Init user manager
        self.user_manager = UserManager(
            database_handler        =     self.database_handler,
            auth_token_manager      =     self.auth_token_manager,
            hasher                  =     self.hasher,
            config                  =     self.config
        )

        # Init channels manager
        self.channels_manager = ChannelsManager(
            database_handler        =       self.database_handler,
            auth_token_manager      =       self.auth_token_manager,
            hasher                  =       self.hasher
        )

        # Init messages manager
        self.messages_manager = MessagesManager(
            database_handler        =       self.database_handler,
            auth_token_manager      =       self.auth_token_manager,
            user_manager            =       self.user_manager,
            hasher                  =       self.hasher
        )

        # Init websockets manager
        self.websockets_manager = WebSocketsManager()

        # Init security checks handlker
        self.security_checks_handler = SecurityChecksHandler(
            database_handler        =   self.database_handler,
            user_manager            =   self.user_manager,
            channels_manager        =   self.channels_manager,
            auth_token_manager      =   self.auth_token_manager
        )
        
        self.is_loaded = True

    def load_database(self, database_uri: str | None = None) -> None:
        """
        Load the database and the database handler.
        """
        if self.config is None and database_uri is None:
            self.load_config()
        
        if database_uri is not None:
            self.database = Database(
                database_uri=database_uri
            )
        else:
            self.database = Database(
                config   =   self.config
            )
        
        database_engine  = self.database.create_database_engine_instance() 

        self.database_handler = DatabaseHandler(
            database_engine     =      database_engine,
            hasher              =      self.hasher,
            config              =      self.config
        )
    
    def load_config(self) -> None:
        """
        Load the config handler and the config model.
        """
        self.config_handler = ConfigHandler()
        
        if not self.config_handler.check_config():
            logger.error(errors.ERROR_NO_CONFIG_FILE_FOUND(self.config_handler.config_file_path))
            # sys.exit(1)
        
        config = self.config_handler.load_config()
        if len(config) == 0:
            self.config = Config()
        else:
            self.config = Config(
                config=config
            )

# PufferBlow's APIs objects loader
api_initializer: APIInitializer = APIInitializer()
