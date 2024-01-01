# Encryption/Decryption manager
from pufferblow_api.src.hasher.hasher import Hasher

# Users manager
from pufferblow_api.src.user.user_manager import UserManager

# Authentification token manager
from pufferblow_api.src.auth.auth_token_manager import AuthTokenManager

# Database
from pufferblow_api.src.database.database import Database
from pufferblow_api.src.database.database_handler import DatabaseHandler

# Channels manager
from pufferblow_api.src.channels.channels_manager import ChannelsManager

# Messages manager
from pufferblow_api.src.messages.messages_manager import MessagesManager

# WebSockets manager
from pufferblow_api.src.websocket.websocket_manager import WebSocketsManager
# Models
from pufferblow_api.src.models.pufferblow_api_config_model import PufferBlowAPIconfig

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
        # PufferBlow-api's config data class
        self.pufferblow_api_config = PufferBlowAPIconfig()

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
