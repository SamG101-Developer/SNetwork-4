from src.crypto_engines.tools.secure_bytes import SecureBytes
import os


class Random:
    GENERATOR = os.urandom

    @staticmethod
    def random_bytes(length: int) -> SecureBytes:
        return SecureBytes(Random.GENERATOR(length))
