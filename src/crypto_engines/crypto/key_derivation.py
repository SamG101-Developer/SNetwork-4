from src.crypto_engines.tools.secure_bytes import SecureBytes
from argon2 import PasswordHasher as Argon2


class KDF:
    """
    Key derivation is sued to derive multiple keys from a single master key. This is better than performing multiple
    key exchanges, as it is more efficient as it only requires a single initial key exchange.
    """

    @staticmethod
    def derive_key(master_key: SecureBytes, customization_bytes: SecureBytes, tag_length: int) -> SecureBytes:
        # Derive a key from the master key and customization bytes.
        argon2 = Argon2(hash_len=tag_length)
        derived_key = argon2.hash(master_key.raw + customization_bytes.raw).encode()
        return SecureBytes(derived_key)
