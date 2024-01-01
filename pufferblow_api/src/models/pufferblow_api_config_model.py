from pufferblow_api.src.conf_file_reader.load_config import load_config

class PufferBlowAPIconfig:
    """ PufferBlow-api's config model class """
    
    config = load_config() # load config from `config.yaml` file

    # API related parameters
    API_HOST                :       str     =   config["api"][0]["host"]
    API_PORT                :       int     =   config["api"][1]["port"]
    LOGS_PATH               :       str     =   config["api"][2]["logs_path"]
    WORKERS                 :       int     =   config["api"][3]["workers"]

    # Supabase/postgresql related parameters
    SUPABASE_URL            :       str     =   config["supabase"][0]["supabase_url"]
    SUPABASE_KEY            :       str     =   config["supabase"][1]["supabase_key"]
    DATABASE_NAME           :       str     =   config["supabase"][2]["postregsql"][0]["database_name"]
    USERNAME                :       str     =   config["supabase"][2]["postregsql"][1]["username"]
    DATABASE_PASSWORD       :       str     =   config["supabase"][2]["postregsql"][2]["password"]
    DATABASE_HOST           :       str     =   config["supabase"][2]["postregsql"][3]["host"]
    DATABASE_PORT           :       int     =   config["supabase"][2]["postregsql"][4]["port"]   

    # Encryption
    DERIVED_KEY_BYTES       :       int     =   config["encryption"][0]["derived_key_bytes"]
    DERIVED_KEY_ROUNDS      :       int     =   config["encryption"][1]["derived_key_rounds"]
    SALT_ROUNDS             :       int     =   config["encryption"][2]["salt_rounds"]
    
    # Messages related parameters
    MAX_MESSAGE_SIZE        :       int     =   config["messages"][0]["max_message_size"]
    MAX_MESSAGES_PER_PAGE   :       int     =   config["messages"][1]["max_messages_per_page"]
    MIN_MESSAGES_PER_PAGE   :       int     =   config["messages"][2]["min_messages_per_page"]

    # Server info
    SERVER_SHA256           :       str     =   config["server_info"][0]["server_sha256"]
    SERVER_NAME             :       str     =   config["server_info"][1]["server_name"]
    SERVER_DESCRIPTION      :       str     =   config["server_info"][2]["server_description"]
    SERVER_AVATAR_URL       :       str     =   config["server_info"][3]["server_avatar_url"]
    SERVER_MAINTAINER_NAME  :       str     =   config["server_info"][4]["server_maintainer_name"]
    SERVER_WELCOME_MESSAGE  :       str     =   config["server_info"][5]["server_welcome_message"]
