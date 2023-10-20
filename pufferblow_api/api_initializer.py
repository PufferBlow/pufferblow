# Encryption/Decryption manager
from pufferblow_api.src.hasher.hasher import Hasher

# Users manager
from pufferblow_api.src.user.user_manager import UserManager

# Authentification token manager
from pufferblow_api.src.auth.auth_token_manager import AuthTokenManager

# Database
from pufferblow_api.src.database.database_session import DatabaseSession
from pufferblow_api.src.database.database_handler import DatabaseHandler

# Channels manager
from pufferblow_api.src.channels.channels_manager import ChannelsManager

# Models
from pufferblow_api.src.models.pufferblow_api_config_model import PufferBlowAPIconfig

class APIInitilizer(object):
    """
    Api initilizer class handles the start up of all the needed object
    that will be used by the PufferBlow's API

    Attributes:
        pufferblow_api_config (PufferBlowAPIconfig) : A `PufferBlowAPIconfig` object.
        hasher                (Hasher)              : A `Hasher` object.
        database_session      (DatabaseSession)     : A `DatabaseSession` object.
        database_handler      (DatabaseHandler)     : A `DatabaseHandler` object.
        auth_token_manager    (AuthTokenManager)    : A `AuthTokenManager` object.
        user_manager          (UserManager)         : A `UserManger` object.
        Channels_manager      (ChannelsManager)     : A `ChannelsManager` object.
    """
    pufferblow_api_config   :       PufferBlowAPIconfig     =   None
    hasher                  :       Hasher                  =   None
    database_session        :       DatabaseSession         =   None
    database_handler        :       DatabaseHandler         =   None
    auth_token_manager      :       AuthTokenManager        =   None
    user_manager            :       UserManager             =   None
    Channels_manager        :       ChannelsManager         =   None

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
        self.hasher = Hasher()

        # Init Database Connection
        self.database_session = DatabaseSession(
            supabase_url            =   self.pufferblow_api_config.SUPABASE_URL,
            supabase_key            =   self.pufferblow_api_config.SUPABASE_KEY,
            pufferblow_api_config   =   self.pufferblow_api_config
        )

        # Init Database handler
        self.database_handler = DatabaseHandler(
            database_connection_pool    =       self.database_session.database_connection_pool(),
            hasher                      =       self.hasher
        )

        # Init Auth tokens manager
        self.auth_token_manager = AuthTokenManager(
            database_handler        =       self.database_handler,
            hasher                  =       self.hasher
        )

        # Init user manager
        self.user_manager = UserManager(
            database_handler        =       self.database_handler,
            auth_token_manager      =       self.auth_token_manager,
            hasher                  =       self.hasher
        )

        # Init channels manager
        self.channels_manager = ChannelsManager(
            database_handler        =       self.database_handler,
            auth_token_manager      =       self.auth_token_manager,
            hasher                  =       self.hasher
        )

# PufferBlow's APIs objects loader
api_initilizer: APIInitilizer = APIInitilizer()
