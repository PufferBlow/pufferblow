import sqlalchemy

from urllib.parse import quote
from sqlalchemy_utils import database_exists

# Models
from pufferblow.src.models.pufferblow_api_config_model import PufferBlowAPIconfig

class Database(object):
    def __init__(self, pufferblow_api_config: PufferBlowAPIconfig | None = None, database_uri: str | None = None) -> None:
        self.pufferblow_api_config  =   pufferblow_api_config
        
        if pufferblow_api_config is not None:
            self.database_uri = self._create_database_uri(
                username=self.pufferblow_api_config.USERNAME,
                password=self.pufferblow_api_config.DATABASE_PASSWORD,
                host=self.pufferblow_api_config.DATABASE_HOST,
                port=self.pufferblow_api_config.DATABASE_PORT,
                database_name=self.pufferblow_api_config.DATABASE_NAME,
            )
        else:
            self.database_uri = database_uri

    def create_database_engine_instance(self) -> sqlalchemy.create_engine:
        """
        Create a database engine instance to use to interact
        with the database.

        Args:
            None.
        Returns:
            Engine: A database engine object.
        """
        database_engine = sqlalchemy.create_engine(
            url=self.database_uri,
            pool_size=20,
            max_overflow=10,
            pool_recycle=3600*3, # recycled every three hours
            pool_timeout=27
        )

        return database_engine

    @classmethod
    def check_database_existense(cls, database_uri: str) -> bool:
        """
        Checks if the database exists or not.

        Args:
            None.
        
        Returns:
            bool: True if it exists, otherwise False.
        """
        return database_exists(database_uri)

    @classmethod
    def _create_database_uri(cls, username: str, password: str, host: str, port: int, database_name: str) -> str:
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
        # Encoding database creds
        database_name = quote(database_name)
        username = quote(username)
        password = quote(password)
        host = quote(host)
        
        database_uri = f"postgresql+psycopg2://{username}:{password}@{host}:{port}/{database_name}"

        return database_uri
    
