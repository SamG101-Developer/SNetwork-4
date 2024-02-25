from __future__ import annotations

import os, base58
from typing import Optional

from src.crypto_engines.tools.secure_bytes import SecureBytes


class KeyPair:
    _secret_key: Optional[SecureBytes]
    _public_key: Optional[SecureBytes]

    def __init__(self, secret_key: Optional[SecureBytes] = None, public_key: Optional[SecureBytes] = None) -> None:
        self._secret_key = secret_key
        self._public_key = public_key

    @property
    def secret_key(self) -> Optional[SecureBytes]:
        assert self._secret_key is not None
        return self._secret_key

    @property
    def public_key(self) -> Optional[SecureBytes]:
        assert self._public_key is not None
        return self._public_key

    def export(self, file_path: str, file_name: str) -> KeyPair:
        self.secret_key.export(file_path, file_name, ".sk")
        self.public_key.export(file_path, file_name, ".pk")
        return self

    def import_(self, file_path: str, file_name: str) -> KeyPair:
        self._secret_key = SecureBytes().import_(file_path, file_name, ".sk")
        self._public_key = SecureBytes().import_(file_path, file_name, ".pk")
        return self

    def both(self) -> tuple[SecureBytes, SecureBytes]:
        return self.secret_key, self.public_key


class KEMKeyPair:
    _encapsulated_key: SecureBytes
    _decapsulated_key: SecureBytes

    def __init__(self, encapsulated_key: SecureBytes, decapsulated_key: SecureBytes) -> None:
        self._encapsulated_key = encapsulated_key
        self._decapsulated_key = decapsulated_key

    @property
    def encapsulated_key(self) -> SecureBytes:
        return self._encapsulated_key

    @property
    def decapsulated_key(self) -> SecureBytes:
        return self._decapsulated_key
