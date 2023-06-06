import os
import bcrypt
import base64
import binascii

from rich import print
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from pufferblow_api.src.models.encryption_key_model import EncryptionKey

class Hasher (object):
    """ Hasher class used to encrypt and decrypt passwords, messages, usernames, user's email """
    def __init__(self) -> None:
        pass

    def encrypt(self, data: str):
        """ 
            Encrypt the data using Blowfish algorithm.
            It uses CBC (Cipher Block Chaining) mode 
            and pads the input data using PKCS7 padding.
        """
        generate_key    =      self._generate_key(data)
        key             =      generate_key["derived_key"]
        salt            =      generate_key["salt"]
        
        cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        ciphertext = cipher.encrypt(pad(data.encode("utf-8"), Blowfish.block_size))
        
        encrypted_data = cipher.iv + ciphertext

        encryption_key = EncryptionKey()

        encryption_key.key_value =  base64.b64encode(key).decode("ascii") # Encoding the key into base64 to save in the database
        encryption_key.salt      =  base64.b64encode(salt).decode("ascii") # Encoding the salt into bse64 to save in the database
        
        return [
            encrypted_data,
            encryption_key
        ]
    
    def decrypt(self, encrypted_data: bytes, key: str):
        """ Decrypts the encrypted data """
        key = base64.b64decode(key)  # Convert key from Base64 string to bytes
        iv = encrypted_data[:Blowfish.block_size]
        ciphertext = encrypted_data[Blowfish.block_size:]
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)

        return decrypted_data.decode()

    def _generate_key(self, data: str) -> dict:
        """ Generates a key to encrypt data """
        salt = bcrypt.gensalt()

        derived_key = bcrypt.kdf(
            password=data.encode(),
            salt=salt,
            desired_key_bytes=32,  # Adjust the key length as per your requirement
            rounds=100  # Adjust the number of rounds as per your requirement
        )

        print({
            "salt": salt,
            "derived_key": derived_key
        })

        return {
            "salt": salt,
            "derived_key": derived_key
        }
