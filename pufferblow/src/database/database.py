import sqlalchemy

# Models
from pufferblow.src.models.pufferblow_api_config_model import PufferBlowAPIconfig

class Database(object):
    def __init__(self, supabase_url: str, supabase_key: str, pufferblow_api_config: PufferBlowAPIconfig) -> None:
        self.supabase_url           =   supabase_url
        self.supabase_key           =   supabase_key
        self.pufferblow_api_config  =   pufferblow_api_config

    def create_database_engine_instance(self) -> sqlalchemy.create_engine:
        """
        Create a database engine instance to use to interact
        with the database

        Args:
            `None`.
        
        Returns:

        """
        # TODO: check if the database is live before return the engine
        database_uri = self._create_database_uri(
            username=self.pufferblow_api_config.USERNAME,
            password=self.pufferblow_api_config.DATABASE_PASSWORD,
            host=self.pufferblow_api_config.DATABASE_HOST,
            port=self.pufferblow_api_config.DATABASE_PORT,
            database_name=self.pufferblow_api_config.DATABASE_NAME,
        )

        database_engine = sqlalchemy.create_engine(
            url=database_uri,
            pool_size=20,
            max_overflow=10,
            pool_recycle=3600*3, # All the pool gets recycled every three hours
            pool_timeout=27
        )

        return database_engine

    def _create_database_uri(self, username: str, password: str, host: str, port: int, database_name: str) -> str:
        """
        Create a database uri to use to connect
        to the database

        Args:
            `username` (str): The `username` used to authenticate the database connection.
            `password` (str): The `password` associated with the username.
            `host` (str): The `hostname` or IP address of the database server.
            `port` (int): The `port` number for the database server.
            `database_name` (str): The name of the specific `database` or instance to connect to.

        Returns:
            str: the created database uri.
        """
        # The database type that is supported is postgreSQL
        # because it is used by default in supabase.
        database_uri = f"postgresql+psycopg2://{username}:{password}@{host}:{port}/{database_name}"

        return database_uri
    