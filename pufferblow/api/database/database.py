from urllib.parse import quote

import sqlalchemy
from sqlalchemy_utils import database_exists

# Models
from pufferblow.api.models.config_model import Config


class Database:
    """Database class."""
    def __init__(
        self, config: Config | None = None, database_uri: str | None = None
    ) -> None:
        """Initialize the instance."""
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
        engine_kwargs = {"url": self.database_uri}
        if self.database_uri and str(self.database_uri).startswith("sqlite://"):
            engine_kwargs["connect_args"] = {"check_same_thread": False}
        else:
            engine_kwargs.update(
                {
                    "pool_size": 20,
                    "max_overflow": 10,
                    "pool_recycle": 1800,    # recycle every 30 min
                    "pool_timeout": 27,
                    "pool_pre_ping": True,   # validate connection on checkout
                    # TCP keepalives at the OS level. Without these, an idle
                    # connection sitting between FastAPI and Postgres can be
                    # silently killed by an intermediate firewall / NAT /
                    # cloud load balancer after as little as 60s of silence,
                    # producing "server closed the connection unexpectedly"
                    # on the next query. pool_pre_ping only validates at
                    # checkout — it can't help if the connection dies
                    # mid-query. Keepalives close that gap by keeping the
                    # TCP path warm.
                    #
                    # The values mirror what psycopg2 / libpq recommend for
                    # cloud-hosted Postgres:
                    #   keepalives=1                  enable
                    #   keepalives_idle=30            send first probe after 30s idle
                    #   keepalives_interval=10        probe interval
                    #   keepalives_count=3            give up after 3 missed probes
                    "connect_args": {
                        "keepalives": 1,
                        "keepalives_idle": 30,
                        "keepalives_interval": 10,
                        "keepalives_count": 3,
                    },
                }
            )

        database_engine = sqlalchemy.create_engine(**engine_kwargs)
        self.database_engine = database_engine

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
    def _create_database_uri(
        cls,
        username: str,
        password: str,
        host: str,
        port: int,
        database_name: str,
        ssl_mode: str = "prefer",
        ssl_cert: str | None = None,
        ssl_key: str | None = None,
        ssl_root_cert: str | None = None,
    ) -> str:
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

        database_uri = (
            f"postgresql+psycopg2://{username}:{password}@{host}:{port}/{database_name}"
        )

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
