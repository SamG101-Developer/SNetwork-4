from cryptography.hazmat.primitives.hashes import Hash, SHA3_512


class Hashing:
    """
    Hashing is used to produce fixed length messages from any length input. This keeps signatures short, and is also
    used to ensure that a party knows a secret without revealing the secert.
    """

    ALGORITHM = SHA3_512
    DIGEST_SIZE = ALGORITHM.digest_size
    BLOCK_SIZE = ALGORITHM.block_size

    @staticmethod
    def hash(input_bytes: bytes) -> bytes:
        # Hash the input bytes and return the result.
        hash_engine = Hash(Hashing.ALGORITHM())
        hash_engine.update(input_bytes)
        hashed = bytes(hash_engine.finalize())
        return hashed
