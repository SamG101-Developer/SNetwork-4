from __future__ import annotations

from typing import List, Tuple
from cryptography.hazmat.primitives.constant_time import bytes_eq
import base58, pickle, os


class SecureBytes:
    """
    The SecureBytes class is used to wrap bytes and provide a secure way to handle them. It provides some additional
    utility methods, and ultimately will be moved to a class in C/Rust where the bytes will be stored in a secure
    location and be cleaned up safely after use.
    """

    _bytes: bytes
    _pickled: bool

    def __init__(self, input_bytes: bytes = b"", pickled: bool = False) -> None:
        # Assign the input bytes to the object.
        self._bytes = input_bytes
        self._pickled = pickled

    @staticmethod
    def from_random(length: int) -> SecureBytes:
        # Create a SecureBytes object from random bytes.
        from crypto_engines.tools.random import Random
        return Random.random_bytes(length)

    @staticmethod
    def from_int(input_int: int) -> SecureBytes:
        # Create a SecureBytes object from an integer.
        return SecureBytes(input_int.to_bytes(input_int.bit_length() // 8 + 1, "big"))

    def merge(self, that: SecureBytes) -> SecureBytes:
        # Merge the bytes of two SecureBytes objects and return a new SecureBytes object.
        if self._pickled:
            items = pickle.loads(self._bytes)
            new_items = (*items, that._bytes)
            return SecureBytes(pickle.dumps(new_items), pickled=True)

        new_items = (self._bytes, that._bytes)
        return SecureBytes(pickle.dumps(new_items), pickled=True)

    def unmerge(self, max_parts: int = 1) -> List[SecureBytes]:
        # Unmerge the bytes of a SecureBytes object and return a list of new SecureBytes objects.
        cur_items = pickle.loads(self._bytes)
        return [SecureBytes(item) for item in cur_items[:max_parts]]

    def split_at(self, index: int) -> Tuple[SecureBytes, SecureBytes]:
        # Split the bytes of a SecureBytes object at a specified index and return two new SecureBytes objects.
        return SecureBytes(self._bytes[:index]), SecureBytes(self._bytes[index:])

    def to_int(self) -> int:
        # Convert the bytes of a SecureBytes object to an integer and return it.
        return int.from_bytes(self._bytes, "big")

    def export(self, file_path: str, file_name: str, extension: str = ".txt") -> SecureBytes:
        os.makedirs(file_path, exist_ok=True)

        encoded_bytes = base58.b58encode(self._bytes)
        formatted_bytes = b"\n".join([encoded_bytes[i:i + 64] for i in range(0, len(encoded_bytes), 64)])
        open(f"{file_path}/{file_name}{extension}", "wb").write(formatted_bytes)
        return self

    def import_(self, file_path: str, file_name: str, extension: str = ".txt") -> SecureBytes:
        encoded_bytes = open(f"{file_path}/{file_name}{extension}", "rb").read()
        formatted_bytes = b"".join(encoded_bytes.split(b"\n"))
        self._bytes = base58.b58decode(formatted_bytes)
        return self

    def __eq__(self, that: SecureBytes) -> bool:
        # Compare the bytes of two SecureBytes objects with a constant time comparison.
        from crypto_engines.crypto.hashing import Hashing
        hash_lhs = Hashing.hash(self).raw
        hash_rhs = Hashing.hash(that).raw
        return bytes_eq(hash_lhs, hash_rhs)

    def __ne__(self, that: SecureBytes) -> bool:
        # Compare the bytes of two SecureBytes objects with a constant time comparison.
        return not self.__eq__(that)

    def __add__(self, that: SecureBytes) -> SecureBytes:
        # Concatenate the bytes of two SecureBytes objects and return a new SecureBytes object.
        return SecureBytes(self._bytes + that._bytes)

    def __radd__(self, that: SecureBytes) -> SecureBytes:
        # Concatenate the bytes of two SecureBytes objects and return a new SecureBytes object.
        return SecureBytes(that._bytes + self._bytes)

    def __str__(self) -> str:
        # Convert the bytes of a SecureBytes object to a base58 string and return it.
        return base58.b58encode(self._bytes).decode("utf-8")

    @property
    def length(self) -> int:
        # Return the length of the bytes of a SecureBytes object.
        return len(self._bytes)

    @property
    def raw(self) -> bytes:
        # Return the underlying bytes of a SecureBytes object.
        return self._bytes
