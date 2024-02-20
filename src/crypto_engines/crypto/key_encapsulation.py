from src.crypto_engines.tools.secure_bytes import SecureBytes
from src.crypto_engines.keys.key_pair import KeyPair, KEMKeyPair
from pqcrypto.kem import kyber1024 as Kyber1024


class KEM:
    """
    Key encapsulation is used to encapsulate a key, so that it can be sent to the recipient. There are methods for
    encapsulating, decapsulating and generating key pairs.
    """

    ALGORITHM = Kyber1024

    @staticmethod
    def generate_key_pair() -> KeyPair:
        # Generate a key pair and package it into a KeyPair object.
        public_key, secret_key = KEM.ALGORITHM.generate_keypair()
        return KeyPair(SecureBytes(secret_key), SecureBytes(public_key))

    @staticmethod
    def kem_wrap(their_ephemeral_public_key: SecureBytes) -> KEMKeyPair:
        # Encapsulate the key and package both the encapsulated and decapsulated keys into a KEMKeyPair object.
        encapsulated_key, decapsulated_key = KEM.ALGORITHM.encrypt(their_ephemeral_public_key.raw)
        return KEMKeyPair(SecureBytes(encapsulated_key), SecureBytes(decapsulated_key))

    @staticmethod
    def kem_unwrap(my_ephemeral_secret_key: SecureBytes, encapsulated_key: SecureBytes) -> KEMKeyPair:
        # Decapsulate the key and package both the encapsulated and decapsulated keys into a KEMKeyPair object.
        decapsulated_key = KEM.ALGORITHM.decrypt(my_ephemeral_secret_key.raw, encapsulated_key.raw)
        return KEMKeyPair(encapsulated_key, SecureBytes(decapsulated_key))
