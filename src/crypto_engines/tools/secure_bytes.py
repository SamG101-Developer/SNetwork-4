from __future__ import annotations

from typing import List, Self, Tuple
from cryptography.hazmat.primitives.constant_time import bytes_eq
import base58


class SecureBytes:
    """
    The SecureBytes class is used to wrap bytes and provide a secure way to handle them. It provides some additional
    utility methods, and ultimately will be moved to a class in C/Rust where the bytes will be stored in a secure
    location and be cleaned up safely after use.
    """

    _bytes: bytes
    _delimiter: bytes = b"-"

    def __init__(self, input_bytes: bytes = b"") -> None:
        # Assign the input bytes to the object.
        self._bytes = input_bytes

    @staticmethod
    def from_random(length: int) -> SecureBytes:
        # Create a SecureBytes object from random bytes.
        from src.crypto_engines.tools.random import Random
        return Random.random_bytes(length)

    @staticmethod
    def from_int(input_int: int) -> SecureBytes:
        # Create a SecureBytes object from an integer.
        return SecureBytes(input_int.to_bytes(input_int.bit_length() // 8 + 1, "big"))

    def merge(self, that: Self) -> Self:
        # Merge the bytes of two SecureBytes objects and return a new SecureBytes object.
        return SecureBytes(self._bytes + SecureBytes._delimiter + that._bytes)

    def unmerge(self, max_splits: int = 1) -> List[Self]:
        # Unmerge the bytes of a SecureBytes object and return a list of new SecureBytes objects.
        return [SecureBytes(byte_slice) for byte_slice in self._bytes.split(SecureBytes._delimiter, max_splits)]

    def split_at(self, index: int) -> Tuple[Self, Self]:
        # Split the bytes of a SecureBytes object at a specified index and return two new SecureBytes objects.
        return SecureBytes(self._bytes[:index]), SecureBytes(self._bytes[index:])

    def to_int(self) -> int:
        # Convert the bytes of a SecureBytes object to an integer and return it.
        return int.from_bytes(self._bytes, "big")

    def __eq__(self, that: Self) -> bool:
        # Compare the bytes of two SecureBytes objects with a constant time comparison.
        from src.crypto_engines.crypto.hashing import Hashing
        hash_lhs = Hashing.hash(self).raw
        hash_rhs = Hashing.hash(that).raw
        return bytes_eq(hash_lhs, hash_rhs)

    def __ne__(self, that: Self) -> bool:
        # Compare the bytes of two SecureBytes objects with a constant time comparison.
        return not self.__eq__(that)

    def __add__(self, that: Self) -> Self:
        # Concatenate the bytes of two SecureBytes objects and return a new SecureBytes object.
        return SecureBytes(self._bytes + that._bytes)

    def __radd__(self, that: Self) -> Self:
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
