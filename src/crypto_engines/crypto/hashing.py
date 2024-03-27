from cryptography.hazmat.primitives.hashes import Hash, SHA3_512
from crypto_engines.tools.secure_bytes import SecureBytes


class Hashing:
    """
    Hashing is used to produce fixed length messages from any length input. This keeps signatures short, and is also
    used to ensure that a party knows a secret without revealing the secert.
    """
    ALGORITHM = SHA3_512

    @staticmethod
    def hash(input_bytes: SecureBytes) -> SecureBytes:
        # Hash the input bytes and return the result.
        hash_engine = Hash(Hashing.ALGORITHM())
        hash_engine.update(input_bytes.raw)
        hashed = SecureBytes(hash_engine.finalize())
        return hashed
