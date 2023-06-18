from pufferblow_api.src.conf_file_reader.load_config import load_config

class PufferBlowAPIConfig:
    """ PufferBlow-api's config data class """
    
    CONFIG = load_config()

    API_HOST            :  str     = CONFIG["api"][0]["host"]
    API_PORT            :  int     = CONFIG["api"][1]["port"]
    LOGS_PATH           :  str     = CONFIG["api"][2]["logs_path"]
    WORKERS             :  int     = CONFIG["api"][3]["workers"]
    CONNECTION_TIMEOUT  :  int     = CONFIG["api"][4]["connection_timeout"]
    SUPABASE_URL        :  str     = CONFIG["supabase"][0]["supabase_url"]
    SUPABASE_KEY        :  str     = CONFIG["supabase"][1]["supabase_key"]
    DATABASE_NAME       :  str     = CONFIG["supabase"][2]["postregsql"][0]["database_name"]
    USERNAME            :  str     = CONFIG["supabase"][2]["postregsql"][1]["username"]
    DATABASE_PASSWORD   :  str     = CONFIG["supabase"][2]["postregsql"][2]["password"]
    DATABASE_HOST       :  str     = CONFIG["supabase"][2]["postregsql"][3]["host"]
    DATABASE_PORT       :  int     = CONFIG["supabase"][2]["postregsql"][4]["port"]   
