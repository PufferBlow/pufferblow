from pufferblow_api.src.conf_file_reader.load_config import load_config

class PufferBlowAPIConfig:
    """ PufferBlow-api's config data class """
    
    CONFIG = load_config()

    API_HOST            :  str     = CONFIG["api"][0]["host"]
    API_PORT            :  int     = CONFIG["api"][1]["port"]
    LOGS_PATH           :  str     = CONFIG["api"][2]["logs_path"]
    WORKERS             :  int     = CONFIG["api"][3]["workers"]
    CONNECTION_TIMEOUT  :  int     = CONFIG["api"][4]["connection_timeout"]
    CASSANDRA_HOST      :  str     = CONFIG["cassandra"][0]["host"]
    CASSANDRA_PORT      :  int     = CONFIG["cassandra"][1]["port"]
    USERNAME            :  str     = CONFIG["cassandra"][2]["username"]
    PASSWORD            :  str     = CONFIG["cassandra"][3]["password"]
