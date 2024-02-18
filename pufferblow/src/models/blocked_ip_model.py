import uuid
import random
import string
import hashlib

# Tables
from pufferblow.src.database.tables.blocked_ips import BlockedIPS

# Utils
from pufferblow.src.utils.current_date import date_in_gmt

class BlockedIP(object):
    """
    The BlockedIP is an object that represents an IP address that got banned/blocked by the server owner
    or by the API itself due to suspicious activities.
    """
    ip_id           : str
    ip              : str
    block_reason    : str
    blocked_at      : str | None = date_in_gmt()

    def create_table_metadata(self) -> BlockedIPS:
        """
        Create a `blocked_ips` table row object that contains
        the current BlockedIP's metadata

        Args:
            `None`.
        
        Returns:
            BlockedIPS: A `BlockedIPS` table object.
        """
        blocked_ips_row = BlockedIPS(
            ip_id=self.ip_id,
            ip=self.ip,
            block_reason=self.block_reason,
            blocked_at=self.blocked_at
        )

        return blocked_ips_row

    def load_table_metadata(self, table_metadata: BlockedIPS) -> dict:
        """
        Load metadata from a `BlockedIPS` table row object into
        the `self`'s attributes

        Args:
            `table_metadata` (User): The `BlockedIPS` table object containing the metadata to load.
        
        Returns:
            dict: The metadata formated in dict.
        """
        self.ip_id          =   table_metadata.ip_id
        self.ip             =   table_metadata.ip
        self.block_reason   =   table_metadata.block_reason
        self.blocked_at     =   table_metadata.blocked_at

        return self.to_json()

    def to_json(self) -> dict:
        """ Returns the BlockedIP data in json format """
        blocked_ips_model_data = {
            "ip_id"         :   self.ip_id,
            "ip"            :   self.ip,
            "block_reason"  :   self.block_reason,
            "blocked_at"    :   self.blocked_at
        }

        return blocked_ips_model_data

    def to_tuple(self) -> tuple:
        """ Reutns the channel data in tuple format """
        blocked_ips_model_data = (
            self.ip_id,
            self.ip,
            self.block_reason,
            self.blocked_at
        )

        return blocked_ips_model_data

    def _generate_message_id(self, data: str | None = "") -> str:
        """
        Generate a unique id based on some data.

        Args:
            data (str, optional, default: ""): A random data that will be used to generate the ID, this helps in adding randomness to the ID.
        
        Returns:
            str: The generated id.
        """
        data = f"{data}{''.join([char for char in random.choices(string.ascii_letters)])}" # Adding random charachters to the username

        hashed_data_salt = hashlib.md5(data.encode()).hexdigest()
        generated_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, hashed_data_salt)

        return str(generated_uuid)
