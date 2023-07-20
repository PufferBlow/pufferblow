import psycopg2
import psycopg2.pool

from pufferblow_api.src.models.pufferblow_api_config_model import PufferBlowAPIconfig

class DatabaseSession (object):
    def __init__(self, supabase_url: str, supabase_key: str, pufferblow_api_config: PufferBlowAPIconfig) -> None:
        self.supabase_url = supabase_url
        self.supabase_key = supabase_key
        self.pufferblow_api_config = pufferblow_api_config

    def database_connection_pool(self) -> psycopg2.pool.ThreadedConnectionPool:
        """ Returns the threads database connection pool """
        KEEPALIVE_KWAGS = {
            "keepalives":11,
            "keepalives_idle": 30,
            "keepalives_interval": 11,
            "keepalives_count": 11,
        }

        database_connection = psycopg2.pool.ThreadedConnectionPool(
            minconn=1,
            maxconn=30,
            database=self.pufferblow_api_config.DATABASE_NAME,
            host=self.pufferblow_api_config.DATABASE_HOST,
            user=self.pufferblow_api_config.USERNAME,
            password=self.pufferblow_api_config.DATABASE_PASSWORD,
            port=self.pufferblow_api_config.DATABASE_PORT,
            **KEEPALIVE_KWAGS
        )

        return database_connection
