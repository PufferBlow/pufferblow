
class PufferBlowAPIconfig:
    """ PufferBlow-api's config model class """ 
    # API related parameters
    API_HOST                :       str
    API_PORT                :       int
    LOGS_PATH               :       str
    WORKERS                 :       int

    # Supabase
    SUPABASE_URL            :       str
    SUPABASE_KEY            :       str
    
    # PostgeSQL Database
    DATABASE_NAME           :       str
    USERNAME                :       str
    DATABASE_PASSWORD       :       str
    DATABASE_HOST           :       str
    DATABASE_PORT           :       int  

    # Encryption
    DERIVED_KEY_BYTES       :       int
    DERIVED_KEY_ROUNDS      :       int
    SALT_ROUNDS             :       int
    
    # Messages related parameters
    MAX_MESSAGE_SIZE        :       int
    MAX_MESSAGES_PER_PAGE   :       int
    MIN_MESSAGES_PER_PAGE   :       int

    # Server info
    SERVER_SHA256           :       str
    SERVER_NAME             :       str
    SERVER_DESCRIPTION      :       str
    SERVER_AVATAR_URL       :       str
    SERVER_MAINTAINER_NAME  :       str
    SERVER_WELCOME_MESSAGE  :       str
    
    def __init__(self, config: dict) -> None:
        self.set_attr_from_config(config)

    def set_attr_from_config(self, config: dict) -> None:
        """
        Sets the attributes values from the config file
        
        Args:
            config (dict): The config file data.

        Returns:
            None.
        """
        # API related parameters
        self.API_HOST      =   config["api"]["host"]
        self.API_PORT      =   config["api"]["port"]
        self.LOGS_PATH     =   config["api"]["logs_path"]
        self.WORKERS       =   config["api"]["workers"]

        # Supabase
        self.SUPABASE_URL     =   config["supabase"]["supabase_url"]
        self.SUPABASE_KEY     =   config["supabase"]["supabase_key"]
    
        # PostgeSQL Database
        self.DATABASE_NAME        =   config["supabase"]["postregsql"]["database_name"]
        self.USERNAME             =   config["supabase"]["postregsql"]["username"]
        self.DATABASE_PASSWORD    =   config["supabase"]["postregsql"]["password"]
        self.DATABASE_HOST        =   config["supabase"]["postregsql"]["host"]
        self.DATABASE_PORT        =   config["supabase"]["postregsql"]["port"]   

        # Encryption
        self.DERIVED_KEY_BYTES     =   config["encryption"]["derived_key_bytes"]
        self.DERIVED_KEY_ROUNDS    =   config["encryption"]["derived_key_rounds"]
        self.SALT_ROUNDS           =   config["encryption"]["salt_rounds"]

        # Messages related parameters
        self.MAX_MESSAGE_SIZE        =   config["messages"]["max_message_size"]
        self.MAX_MESSAGES_PER_PAGE   =   config["messages"]["max_messages_per_page"]
        self.MIN_MESSAGES_PER_PAGE   =   config["messages"]["min_messages_per_page"]

        # Server info
        self.SERVER_SHA256              =   config["server_info"]["server_sha256"]
        self.SERVER_NAME                =   config["server_info"]["server_name"]
        self.SERVER_DESCRIPTION         =   config["server_info"]["server_description"]
        self.SERVER_AVATAR_URL          =   config["server_info"]["server_avatar_url"]
        self.SERVER_MAINTAINER_NAME     =   config["server_info"]["server_maintainer_name"]
        self.SERVER_WELCOME_MESSAGE     =   config["server_info"]["server_welcome_message"]

