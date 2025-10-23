import sqlalchemy

from urllib.parse import quote
from sqlalchemy_utils import database_exists

# Models
from pufferblow.api.models.config_model import Config

class Database(object):
    def __init__(self, config: Config | None = None, database_uri: str | None = None) -> None:
        self.config = config 

        if self.config is not None:
            self.database_uri = self._create_database_uri(
                username=self.config.USERNAME,
                password=self.config.DATABASE_PASSWORD,
                host=self.config.DATABASE_HOST,
                port=self.config.DATABASE_PORT,
                database_name=self.config.DATABASE_NAME,
                ssl_mode=self.config.DATABASE_SSL_MODE,
                ssl_cert=self.config.DATABASE_SSL_CERT,
                ssl_key=self.config.DATABASE_SSL_KEY,
                ssl_root_cert=self.config.DATABASE_SSL_ROOT_CERT,
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
            pool_timeout=27,
            pool_pre_ping=True   # prevents stale connections
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
    def _create_database_uri(cls, username: str, password: str, host: str, port: int, database_name: str,
                             ssl_mode: str = "prefer", ssl_cert: str | None = None, ssl_key: str | None = None,
                             ssl_root_cert: str | None = None) -> str:
        """
        Create a database uri to use to connect
        to the database

        Args:
            `username` (str): The `username` used to authenticate the database connection.
            `password` (str): The `password` associated with the username.
            `host` (str): The `hostname` or IP address of the database server.
            `port` (int): The `port` number for the database server.
            `database_name` (str): The name of the specific `database` or instance to connect to.
            `ssl_mode` (str): SSL mode for the connection.
            `ssl_cert` (str | None): Path to SSL client certificate.
            `ssl_key` (str | None): Path to SSL client private key.
            `ssl_root_cert` (str | None): Path to SSL root certificate.

        Returns:
            str: the created database uri.
        """
        # Encoding database creds
        database_name = quote(database_name)
        username = quote(username)
        password = quote(password)
        host = quote(host)

        database_uri = f"postgresql+psycopg2://{username}:{password}@{host}:{port}/{database_name}"

        # Add SSL parameters as query string
        params = []
        if ssl_mode:
            params.append(f"sslmode={quote(ssl_mode)}")
        if ssl_cert:
            params.append(f"sslcert={quote(ssl_cert)}")
        if ssl_key:
            params.append(f"sslkey={quote(ssl_key)}")
        if ssl_root_cert:
            params.append(f"sslrootcert={quote(ssl_root_cert)}")

        if params:
            database_uri += "?" + "&".join(params)

        return database_uri
