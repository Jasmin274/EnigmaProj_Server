"""
Name: Jasmin Maizel
Final Project subject: Cryptography - Enigma
this is the RSA file, encrypts and decrypts texts with RSA
Python Version: 3.7.4
Date: 10.02.2021
"""

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class RSA_encryption:
    """
    this class is for the RSA encryption. It generates a pair of keys - public and private,
    and encrypts and decrypts texts with RSA encryption.
    """

    def __init__(self):
        """
        generates the RSA keys.
        """
        self.__keyPair = RSA.generate(3072)
        self.__pubKey = self.__keyPair.publickey()

    def get_public_key(self):
        """
        :return: the public key
        """
        return self.__pubKey.exportKey()

    def decrypt(self, cipher_text):
        """
        decrypts text using the private key
        :param cipher_text:
        :return: the decrypted text
        """
        rsa_private_key = RSA.importKey(self.__keyPair.export_key())
        rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
        decrypted_text = rsa_private_key.decrypt(cipher_text)
        return decrypted_text

    @staticmethod
    def encrypt(plain_text, public_key):
        """
        this method encrypts text using a given public key
        :param plain_text:
        :param public_key:
        :return: encrypted text
        """
        public_key = RSA.importKey(public_key)
        encryptor = PKCS1_OAEP.new(public_key)
        encrypted = encryptor.encrypt(plain_text)
        return encrypted
