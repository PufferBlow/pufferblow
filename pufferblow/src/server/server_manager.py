import uuid
import string
import random
import hashlib

# Database handler
from pufferblow.src.database.database_handler import DatabaseHandler

# Tables
from pufferblow.src.database.tables.server import Server

class ServerManager:
    """
    the server manager class
    """
    def __init__(self, database_handler: DatabaseHandler) -> None:
        self.database_handler = database_handler

    def create_server(self, server_name: str, server_welcome_message: str,  description: str | None = None) -> None:
        """
        Creates a server which will contain all
        of the info about the server.

        Args:
            sever_name (str): The server's name.
            server_description (str, default: None, Optional): The server's description.
            server_welcome_message (str): The server's welcome for new members.
        
        Returns:
            None.
        """
        server = Server(
            server_id=self._generate_user_id(server_name=server_name),
            server_name=server_name,
            description=description,
            server_welcome_message=server_welcome_message,
        )

        self.database_handler.create_server_row(server=server)

    def update_server(self, server_name: str, server_welcome_message: str, description: str | None = None) -> None:
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
            server_welcome_message=server_welcome_message
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

