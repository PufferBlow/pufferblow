import bcrypt
import base64
import datetime

from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import (
    pad,
    unpad
)

from pufferblow.src.models.salt_model import Salt
from pufferblow.src.models.encryption_key_model import EncryptionKey

class Hasher(object):
    """
    Hasher class used to encrypt and decrypt data,
    it support two types of encryptions, the first
    been BlowFish and the second Bcrypt.
    """
    def __init__(self, derived_key_bytes: int, derived_key_rounds: int, salt_rounds: int) -> None:
        self.derived_key_bytes      =     derived_key_bytes
        self.derived_key_rounds     =     derived_key_rounds
        self.salt_rounds            =     salt_rounds

    def encrypt_with_blowfish(self, data: str, is_to_check: bool | None = False, key: bytes | None=None) -> tuple[str, EncryptionKey] | str:
        """
        Encrypt the data using Blowfish algorithm.
        It uses CBC (Cipher Block Chaining) mode 
        and pads the input data using PKCS7 padding.

        Args:
            `data` (str): The `data` to encrypt.
            `is_to_check` (bool, optional, default: False): If set to `True` then no encryption key object will get created to save in the database.
            `key` (bytes, optional, default: None): A `key` to encrypt the data (only get passed in when `is_to_check` is set to `True`).
        
        Returns:
            tuple[str, str]: Containing the encrypted data and the encryption key.
            str: The encrypted data.
        """
        if key is None:
            key = self._generate_key(data)
        else:
            key = base64.b64decode(key)
            
        cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        ciphertext = cipher.encrypt(pad(data.encode("utf-8"), Blowfish.block_size))
        
        encrypted_data = cipher.iv + ciphertext
        
        if is_to_check != True:
            encryption_key = EncryptionKey()
            encryption_key.key_value = base64.b64encode(key).decode("ascii") # Encoding the key into base64 to save in the database

            return (
                encrypted_data,
                encryption_key
            )
        else:
            return encrypted_data
    
    def decrypt_with_blowfish(self, encrypted_data: bytes, key: str) -> str:
        """
        Decrypts the encrypted data
        
        Args:
            `encrypted_data` (bytes): The encrypted data to decrypt.
            `key` (str): The `key` used to encrypt the data.
        
        Returns:
            str: The decrypted data.
        """
        key = base64.b64decode(key)  # Convert key from Base64 string to bytes

        iv = encrypted_data[:Blowfish.block_size]
        ciphertext = encrypted_data[Blowfish.block_size:]
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        
        decrypted_data = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)

        return decrypted_data.decode()

    def encrypt_with_bcrypt(self, data: str, user_id: str = "", salt: str | None=None, is_to_check: bool = False) -> Salt:
        """ 
        Used to encrypt data using a Bcrypt
        
        Parameters:
            `user_id` (str): The user's `user_id`.
            `data` (str): The `data` to encrypt.

        Returns:
            Salt
        """
        _salt = Salt()

        if is_to_check:
            _salt.salt_value = salt
            
            hashed_data = bcrypt.hashpw(
                data.encode("utf-8"),
               _salt.salt_value
            )
            
            return hashed_data

        _salt.salt_value   =   bcrypt.gensalt(
            rounds=self.salt_rounds
        )

        _salt.user_id           =   user_id
        _salt.associated_to     =   ""
        _salt.created_at        =   datetime.date.today().strftime("%Y-%m-%d")

        hashed_data = bcrypt.hashpw(
            data.encode("utf-8"),
            _salt.salt_value
        )

        _salt.salt_value  = base64.b64encode(_salt.salt_value).decode("ascii")
        _salt.hashed_data = base64.b64encode(hashed_data).decode("ascii")
        
        return _salt

    def _generate_key(self, data: str) -> dict:
        """
        Generates a key to encrypt data
        
        Parameters:
            `data` (str): The `data` that the `key` will be derived from (to make it more unique and hard to recreate).
        
        Returns:
            tuple: Contains the drived `key` as well as the `salt` used.
        """
        salt = bcrypt.gensalt()

        derived_key = bcrypt.kdf(
            password=data.encode(),
            salt=salt,
            desired_key_bytes=self.derived_key_bytes,  # Adjust the number of rounds as per your requirement in the config file
            rounds=self.derived_key_rounds  # Adjust the number of rounds as per your requirement in the config file
        )

        return derived_key
