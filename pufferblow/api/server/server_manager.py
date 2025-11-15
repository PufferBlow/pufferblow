import hashlib
import random
import string
import uuid

# Database handler
from pufferblow.api.database.database_handler import DatabaseHandler

# Tables
from pufferblow.api.database.tables.server import Server


class ServerManager:
    """
    the server manager class
    """

    def __init__(self, database_handler: DatabaseHandler) -> None:
        self.database_handler = database_handler

    def create_server(
        self,
        server_name: str,
        server_welcome_message: str,
        description: str | None = None,
    ) -> None:
        """
        Creates a server which will contain all
        of the info about the server and initializes default roles, privileges, and settings.

        Args:
            sever_name (str): The server's name.
            server_description (str, default: None, Optional): The server's description.
            server_welcome_message (str): The server's welcome for new members.

        Returns:
            None.
        """
        host_port = "127.0.0.1:8000"
        server_id = str(uuid.uuid4())
        stats_id = str(uuid.uuid4())

        server = Server(
            server_id=server_id,
            server_name=server_name,
            description=description,
            welcome_message=server_welcome_message,
            host_port=host_port,
            stats_id=stats_id,
        )

        # Create the server row first
        self.database_handler.create_server_row(server=server)

        # Initialize default privileges, roles, and settings (PostgreSQL only)
        # Skip for SQLite tests since roles/privileges use ARRAY type not supported by SQLite
        # For SQLite, the database URI starts with 'sqlite://'
        database_uri = str(self.database_handler.database_engine.url)
        if not database_uri.startswith("sqlite://"):
            self.database_handler.initialize_default_data()

    def update_server(
        self,
        server_name: str,
        server_welcome_message: str,
        description: str | None = None,
    ) -> None:
        """
        Update the server's info.

        Args:
            sever_name (str): The server's name.
            server_description (str, default: None, Optional): The server's description.
            server_welcome_message (str): The server's welcome for new members.

        Returns:
            None.
        """
        self.database_handler.update_server_values(
            server_name=server_name,
            description=description,
            server_welcome_message=server_welcome_message,
        )

    def check_server_exists(self) -> bool:
        """
        Checks if the server already which means if it have already
        been setup.

        Args:
            None.

        Returns:
            bool: True if it exists, otherwise False is returned.
        """
        # Skip server checks for SQLite tests since the server table is excluded
        database_uri = str(self.database_handler.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return False

        server = self.database_handler.get_server()

        return not (server == None)

    def _generate_user_id(self, server_name: str) -> str:
        """
        Generate a unique `server_id` based of the server's name.

        Args:
            server_name (str): The server's name.

        Returns:
            str: The generated id.
        """
        server_name = f"{server_name}{''.join([char for char in random.choices(string.ascii_letters)])}"

        hashed_username_salt = hashlib.md5(server_name.encode()).hexdigest()
        generated_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, hashed_username_salt)

        return str(generated_uuid)
