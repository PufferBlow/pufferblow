import os
import sys
import psycopg2
import psycopg2.pool
import datetime

from supabase import (
    create_client,
    Client
)

from pufferblow_api.src.models.pufferblow_api_config_model import PufferBlowAPIConfig

class DatabaseSession (object):
    def __init__(self, supabase_url: str, supabase_key: str, pufferblow_api_config: PufferBlowAPIConfig) -> None:
        self.supabase_url = supabase_url
        self.supabase_key = supabase_key
        self.pufferblow_api_config = pufferblow_api_config

    def database_connection_pool(self) -> psycopg2.pool.ThreadedConnectionPool:
        """ Returns the threads database connection pool """
        KEEPALIVE_KWAGS = {
            "keepalives": 7,
            "keepalives_idle": 30,
            "keepalives_interval": 7,
            "keepalives_count": 7,
        }

        database_connection = psycopg2.pool.ThreadedConnectionPool(
            minconn=1,
            maxconn=20,
            database=self.pufferblow_api_config.DATABASE_NAME,
            host=self.pufferblow_api_config.DATABASE_HOST,
            user=self.pufferblow_api_config.USERNAME,
            password=self.pufferblow_api_config.DATABASE_PASSWORD,
            port=self.pufferblow_api_config.DATABASE_PORT,
            **KEEPALIVE_KWAGS
        )

        return database_connection
