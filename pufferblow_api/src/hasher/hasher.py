import os
import bcrypt
import base64
import datetime

from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad

from pufferblow_api.src.models.salt_model import Salt
from pufferblow_api.src.models.encryption_key_model import EncryptionKey

class Hasher (object):
    """ Hasher class used to encrypt and decrypt passwords, messages, usernames """
    def __init__(self) -> None:
        pass

    def encrypt_with_blowfish(self, data: str, is_to_check: bool | None=False, key: bytes | None=None):
        """
            Encrypt the data using Blowfish algorithm.
            It uses CBC (Cipher Block Chaining) mode 
            and pads the input data using PKCS7 padding.
        """
        if key is None:
            generate_key    =      self._generate_key(data)
            key             =      generate_key[0]
            salt            =      generate_key[1]
        else:
            key = base64.b64decode(key)
            
        cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        ciphertext = cipher.encrypt(pad(data.encode("utf-8"), Blowfish.block_size))
        
        encrypted_data = cipher.iv + ciphertext
        
        if is_to_check != True:
            encryption_key = EncryptionKey()
            encryption_key.key_value =  base64.b64encode(key).decode("ascii") # Encoding the key into base64 to save in the database
            encryption_key.salt      =  base64.b64encode(salt).decode("ascii") # Encoding the salt into bse64 to save in the database

            return (
                encrypted_data,
                encryption_key
            )
        else:
            return encrypted_data
    
    def decrypt_with_blowfish(self, encrypted_data: bytes, key: str) -> str:
        """
        Decrypts the encrypted data
        
        Parameters:
            encrypted_data (bytes): The encrypted data to decrypt
            key (str): The key used in the encryption of the data
        
        Returns:
            str: The decrypted version of the encrypted data
        """
        key = base64.b64decode(key)  # Convert key from Base64 string to bytes

        iv = encrypted_data[:Blowfish.block_size]
        ciphertext = encrypted_data[Blowfish.block_size:]
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)

        return decrypted_data.decode()

    def _generate_key(self, data: str) -> dict:
        """
        Generates a key to encrypt data
        
        Parameters:
            data (str): The data that the key will be derived from
        
        Returns:
            tuple: Contains the drived key as well as the salt used
        """
        salt = bcrypt.gensalt()

        derived_key = bcrypt.kdf(
            password=data.encode(),
            salt=salt,
            desired_key_bytes=32,  # Adjust the key length as per your requirement
            rounds=100  # Adjust the number of rounds as per your requirement
        )

        return (
            derived_key,
            salt
        )

    def encrypt_with_bcrypt(self, data: str, user_id: str = "", salt: str | None=None, is_to_check: bool = False) -> Salt:
        """ 
        Used to encrypt data using a Bcrypt
        
        Parameters:
            user_id (str): The user's id
            data (str): The data to hash

        Returns:
            Salt object
        """
        _salt = Salt()

        if is_to_check:
            _salt.salt_value = salt
            
            hashed_data = bcrypt.hashpw(
                data.encode("utf-8"),
               _salt.salt_value
            )

            return hashed_data

        _salt.salt_value   =    bcrypt.gensalt()

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
