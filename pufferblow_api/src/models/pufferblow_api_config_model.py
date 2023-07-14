from pufferblow_api.src.conf_file_reader.load_config import load_config

class PufferBlowAPIconfig:
    """ PufferBlow-api's config data class """
    
    config = load_config()

    API_HOST            :  str     = config["api"][0]["host"]
    API_PORT            :  int     = config["api"][1]["port"]
    LOGS_PATH           :  str     = config["api"][2]["logs_path"]
    WORKERS             :  int     = config["api"][3]["workers"]
    CONNECTION_TIMEOUT  :  int     = config["api"][4]["connection_timeout"]
    SUPABASE_URL        :  str     = config["supabase"][0]["supabase_url"]
    SUPABASE_KEY        :  str     = config["supabase"][1]["supabase_key"]
    DATABASE_NAME       :  str     = config["supabase"][2]["postregsql"][0]["database_name"]
    USERNAME            :  str     = config["supabase"][2]["postregsql"][1]["username"]
    DATABASE_PASSWORD   :  str     = config["supabase"][2]["postregsql"][2]["password"]
    DATABASE_HOST       :  str     = config["supabase"][2]["postregsql"][3]["host"]
    DATABASE_PORT       :  int     = config["supabase"][2]["postregsql"][4]["port"]   
