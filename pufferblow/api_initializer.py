import sys
from loguru import logger

# Encryption/Decryption manager
from pufferblow.src.hasher.hasher import Hasher

# Config handler
from pufferblow.src.config.config_handler import ConfigHandler

# Users manager
from pufferblow.src.user.user_manager import UserManager

# Authentification token manager
from pufferblow.src.auth.auth_token_manager import AuthTokenManager

# Database
from pufferblow.src.database.database import Database
from pufferblow.src.database.database_handler import DatabaseHandler

# Channels manager
from pufferblow.src.channels.channels_manager import ChannelsManager

# Messages manager
from pufferblow.src.messages.messages_manager import MessagesManager

# WebSockets manager
from pufferblow.src.websocket.websocket_manager import WebSocketsManager

# Models
from pufferblow.src.models.pufferblow_api_config_model import PufferBlowAPIconfig

# Log messages
from pufferblow.src.logger.msgs import (
    errors    
)

class APIInitializer(object):
    """
    Api initializer class handles the start up of all the needed object
    that will be used by the PufferBlow's API

    Attributes:
        pufferblow_api_config (PufferBlowAPIconfig) : A `PufferBlowAPIconfig` object.
        hasher                (Hasher)              : A `Hasher` object.
        database              (Database)            : A `Database` object.
        database_handler      (DatabaseHandler)     : A `DatabaseHandler` object.
        auth_token_manager    (AuthTokenManager)    : A `AuthTokenManager` object.
        user_manager          (UserManager)         : A `UserManger` object.
        Channels_manager      (ChannelsManager)     : A `ChannelsManager` object.
    """
    pufferblow_api_config   :       PufferBlowAPIconfig     =   None
    hasher                  :       Hasher                  =   None
    database                :       Database                =   None
    database_handler        :       DatabaseHandler         =   None
    auth_token_manager      :       AuthTokenManager        =   None
    user_manager            :       UserManager             =   None
    channels_manager        :       ChannelsManager         =   None
    websockets_manager      :       WebSocketsManager       =   None

    def __init__(self) -> None:
        pass
    
    def load_objects(self) -> None:
        """
        Load all the objects that will be used by the API

        Args:
            `None`.
        
        Returns:
            `None`.
        """
        # Config handler
        self.config_handler = ConfigHandler()
        
        if not self.config_handler.check_config():
            logger.error(errors.ERROR_NO_CONFIG_FILE_FOUND(self.config_handler.config_file_path))
            sys.exit(1)

        # PufferBlow-api's config data class
        self.pufferblow_api_config = PufferBlowAPIconfig(
            config=self.config_handler.load_config()
        )

        # Init the hasher (Responsible for encrypting and decrypting data)
        self.hasher = Hasher(
            derived_key_bytes       =       self.pufferblow_api_config.DERIVED_KEY_BYTES,
            derived_key_rounds      =       self.pufferblow_api_config.DERIVED_KEY_ROUNDS,
            salt_rounds             =       self.pufferblow_api_config.SALT_ROUNDS
        )

        # Init Database Connection
        self.database = Database(
            supabase_url            =   self.pufferblow_api_config.SUPABASE_URL,
            supabase_key            =   self.pufferblow_api_config.SUPABASE_KEY,
            pufferblow_api_config   =   self.pufferblow_api_config
        )

        # Init Database handler
        database_engine  = self.database.create_database_engine_instance()
        
        self.database_handler = DatabaseHandler(
            database_engine         =      database_engine,
            hasher                  =      self.hasher,
            pufferblow_config_model =      self.pufferblow_api_config
        )

        # Init Auth tokens manager
        self.auth_token_manager = AuthTokenManager(
            database_handler        =       self.database_handler,
            hasher                  =       self.hasher
        )

        # Init user manager
        self.user_manager = UserManager(
            database_handler          =     self.database_handler,
            auth_token_manager        =     self.auth_token_manager,
            hasher                    =     self.hasher,
            pufferblow_config_model   =     self.pufferblow_api_config
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

# PufferBlow's APIs objects loader
api_initializer: APIInitializer = APIInitializer()
