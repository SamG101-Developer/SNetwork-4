from cryptography.hazmat.primitives.ciphers.aead import AESOCB3
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap
from crypto_engines.tools.secure_bytes import SecureBytes
from crypto_engines.tools.random import Random


class SymmetricEncryption:
    """
    Symmetric encryption is used to secure connections, providing confidentiality and integrity. It is used to encrypt
    and decrypt data, and to wrap and unwrap new keys.
    """

    ALGORITHM    = AESOCB3
    KEY_LENGTH   = 32
    NONCE_LENGTH = 12

    @staticmethod
    def generate_key() -> SecureBytes:
        # Generate a random key and return it.
        random_key = Random.random_bytes(SymmetricEncryption.KEY_LENGTH)
        return random_key

    @staticmethod
    def wrap_new_key(current_key: SecureBytes, new_key: SecureBytes) -> SecureBytes:
        # Wrap the new key using the current key and return it.
        wrapped_key = aes_key_wrap(current_key.raw, new_key.raw)
        return SecureBytes(wrapped_key)

    @staticmethod
    def unwrap_new_key(current_key: SecureBytes, wrapped_key: SecureBytes) -> SecureBytes:
        # Unwrap the new key using the current key and return it.
        unwrapped_key = aes_key_unwrap(current_key.raw, wrapped_key.raw)
        return SecureBytes(unwrapped_key)

    @staticmethod
    def encrypt(data: SecureBytes, key: SecureBytes) -> SecureBytes:
        # Generate a random nonce, encrypt the plaintext and return it with the nonce prepended.
        nonce = Random.random_bytes(SymmetricEncryption.NONCE_LENGTH)
        encryption_engine = SymmetricEncryption.ALGORITHM(key.raw)
        ciphertext = encryption_engine.encrypt(nonce.raw, data.raw, None)
        return SecureBytes(nonce.raw + ciphertext)

    @staticmethod
    def decrypt(data: SecureBytes, key: SecureBytes) -> SecureBytes:
        # Split the nonce anc ciphertext, decrypt the data and return it.
        nonce, ciphertext = data.split_at(SymmetricEncryption.NONCE_LENGTH)
        decryption_engine = SymmetricEncryption.ALGORITHM(key.raw)
        plaintext = decryption_engine.decrypt(nonce.raw, ciphertext.raw, None)
        return SecureBytes(plaintext)
