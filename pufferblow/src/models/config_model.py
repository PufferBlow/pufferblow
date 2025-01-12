from pufferblow import constants

class Config:
    """ config model class """ 
    # API related parameters
    API_HOST                :       str     =       "127.0.0.1"
    API_PORT                :       int     =       7575
    LOGS_PATH               :       str     =       f"{constants.HOME}/logs/pufferblow_api.log"     
    WORKERS                 :       int     =       7
    RATE_LIMIT_DURATION     :       int     =       5
    MAX_RATE_LIMIT_REQUESTS :       int     =       6000
    MAX_RATE_LIMIT_WARNINGS :       int     =       15

    # PostgeSQL Database
    DATABASE_NAME           :       str
    USERNAME                :       str
    DATABASE_PASSWORD       :       str
    DATABASE_HOST           :       str
    DATABASE_PORT           :       int  

    # Encryption
    DERIVED_KEY_BYTES       :       int     =       56
    DERIVED_KEY_ROUNDS      :       int     =       100
    
    # Messages related parameters
    MAX_MESSAGE_SIZE        :       int     =       1024
    MAX_MESSAGES_PER_PAGE   :       int     =       50
    MIN_MESSAGES_PER_PAGE   :       int     =       20
   
    def __init__(self, config: dict | None = None) -> None:
        if config is not None:    
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
        self.API_HOST                   =   config["api"]["host"]
        self.API_PORT                   =   config["api"]["port"]
        self.LOGS_PATH                  =   config["api"]["logs_path"]
        self.WORKERS                    =   config["api"]["workers"]
        self.RATE_LIMIT_DURATION        =   config["api"]["rate_limit_duration"]
        self.MAX_RATE_LIMIT_REQUESTS    =   config["api"]["max_rate_limit_requests"]
        self.MAX_RATE_LIMIT_WARNINGS    =   config["api"]["max_rate_limit_warnings"]
    
        # PostgeSQL Database
        self.DATABASE_NAME        =   config["supabase"]["postregsql"]["database_name"]
        self.USERNAME             =   config["supabase"]["postregsql"]["username"]
        self.DATABASE_PASSWORD    =   config["supabase"]["postregsql"]["password"]
        self.DATABASE_HOST        =   config["supabase"]["postregsql"]["host"]
        self.DATABASE_PORT        =   config["supabase"]["postregsql"]["port"]   

        # Encryption
        self.DERIVED_KEY_BYTES     =   config["encryption"]["derived_key_bytes"]
        self.DERIVED_KEY_ROUNDS    =   config["encryption"]["derived_key_rounds"]

        # Messages related parameters
        self.MAX_MESSAGE_SIZE        =   config["messages"]["max_message_size"]
        self.MAX_MESSAGES_PER_PAGE   =   config["messages"]["max_messages_per_page"]
        self.MIN_MESSAGES_PER_PAGE   =   config["messages"]["min_messages_per_page"]
   
    def export_toml(self) -> str:
        """
        Exports the attributes into a toml format.

        Args:
            None.

        Returns:
            str: The attributes in the toml format.
        """
        config = f"""# This is the config file for pufferblow-api
# please if you do edit this file you will need
# to restart, in order to apply the changes

[api]
host = "{self.API_HOST}"
port = {self.API_PORT}
logs_path = "{self.LOGS_PATH}"
workers = {self.WORKERS} # number of workers for the ASGI, the higher the better
rate_limit_duration = {self.RATE_LIMIT_DURATION} # the duration of a rate limit of an IP address (in minutes)
max_rate_limit_requests = {self.MAX_RATE_LIMIT_REQUESTS} # number of request before a rate limit warning
max_rate_limit_warnings = {self.MAX_RATE_LIMIT_WARNINGS} # number of rate limit warnings before blocking the IP address

[supabase.postregsql]
database_name = "{self.DATABASE_NAME}"
username = "{self.USERNAME}"
password = "{self.DATABASE_PASSWORD}"
host = "{self.DATABASE_HOST}"
port = "{self.DATABASE_PORT}"

[encryption]
derived_key_bytes = {self.DERIVED_KEY_BYTES} # This specifies the bytes length of the derived key. A 56-bit key provides a good balance between security and performance. The bytes should be 5 to 56 bytes.
derived_key_rounds = {self.DERIVED_KEY_ROUNDS} # This represents the number of iterations for the derived key generation process. A higher value increases the computational effort required, enhancing security but also using more CPU resources.

[messages]
max_message_size = {self.MAX_MESSAGE_SIZE} # This defines the maximum size (in KB) for a message that can be sent. Setting this to a larger value may provide more flexibility, but it could also impact your storage capacity. Please adjust according to your storage resources.
max_messages_per_page = {self.MAX_MESSAGES_PER_PAGE} # This defines the maximum number of messages that can be displayed on each page. A value of 50 is recommended to balance between data load and user experience.
min_messages_per_page = {self.MIN_MESSAGES_PER_PAGE} # This defines the minimum number of messages that can be displayed on each page. A value of 20 is recommended to ensure that there is enough message for the user to engage with on each page.
"""
        return config
    
    def __repr__(self) -> str:
        return f"Config(API_HOST={self.API_HOST!r}, API_PORT={self.API_PORT!r}, WORKERS={self.WORKERS!r}, LOGS_PATH={self.LOGS_PATH!r}, RATE_LIMIT_DURATION={self.RATE_LIMIT_DURATION!r}, MAX_RATE_LIMIT_REQUESTS={self.MAX_RATE_LIMIT_REQUESTS!r}, MAX_RATE_LIMIT_WARNINGS={self.MAX_RATE_LIMIT_WARNINGS!r})"
