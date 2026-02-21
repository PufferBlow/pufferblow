import base64

from os import urandom

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Tables
from pufferblow.api.database.tables.keys import Keys


class Encrypt:
    """
    Encrypt class used to encrypt and decrypt data
    using the AES algorithm.
    """

    PADDING: int = 128

    def __init__(self) -> None:
        """Initialize the instance."""
        pass

    def encrypt(
        self, data: str, is_to_check: bool | None = False, key: bytes | None = None
    ) -> tuple[str, Keys] | str:
        """
        Encrypt the data using AES.

        Args:
            `data` (str): The `data` to encrypt.
            `is_to_check` (bool, optional, default: False): If set to `True` then no encryption key object will get created to save in the database.
            `key` (bytes, optional, default: None): A `key` to encrypt the data (only get passed in when `is_to_check` is set to `True`).

        Returns:
            tuple[str, str]: Containing the encrypted data and the encryption key.
            str: The encrypted data.
        """
        if key is None:
            key = self.__generate_key__(data)
        else:
            key = base64.b64decode(key)

        iv = urandom(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padded_data = self.__add_padding__(data.encode())

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        if is_to_check is not True:
            _key = Keys()
            _key.key_value = base64.b64encode(key).decode("ascii")
            _key.iv = base64.b64encode(iv).decode("ascii")

            return (ciphertext, _key)
        else:
            return ciphertext.decode()

    def decrypt(self, ciphertext: bytes, key: str, iv: str) -> str:
        """
        Decrypts the encrypted data

        Args:
            ciphertext (str): The encrypted data to decrypt.
            key (str): The `key` used to encrypt the data.

        Returns:
            str: The decrypted data.
        """
        key = base64.b64decode(key)
        iv = base64.b64decode(iv)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadded_data = self.__remove_padding__(decrypted_data)

        return unpadded_data.decode()

    def __generate_key__(self, data: str) -> dict:
        """
        Generates a key to encrypt data.

        Parameters:
            data (str): The data that the key will be derived from.

        Returns:
            tuple: Contains the drived key.
        """
        salt = urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )

        derived_key = kdf.derive(data.encode())

        return derived_key

    def __add_padding__(self, data: bytes) -> bytes:
        """
        Add padding to data.
        """
        padding_length = 16 - (len(data) % 16)
        padd = bytes([padding_length] * padding_length)

        return data + padd

    def __remove_padding__(self, data: bytes) -> bytes:
        """
        Remove padding from decrypted data.
        """
        last_byte = data[-1]
        if not 1 <= last_byte <= 16:
            return None

        padding_length = last_byte
        data = data[:-padding_length]

        return data

