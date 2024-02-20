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
        os.makedirs(file_path, exist_ok=True)
        encoded_secret_key = base58.b58encode(self.secret_key.raw)
        encoded_secret_key = b"\n".join([encoded_secret_key[i:i + 64] for i in range(0, len(encoded_secret_key), 64)])
        
        encoded_public_key = base58.b58encode(self.public_key.raw)
        encoded_public_key = b"\n".join([encoded_public_key[i:i + 64] for i in range(0, len(encoded_public_key), 64)])

        with open(f"{file_path}/{file_name}.sk", "wb") as file: file.write(encoded_secret_key)
        with open(f"{file_path}/{file_name}.pk", "wb") as file: file.write(encoded_public_key)
        return self

    def import_(self, file_path: str, file_name: str) -> KeyPair:
        with open(f"{file_path}/{file_name}.sk", "rb") as file: encoded_secret_key = base58.b58decode(file.read().replace(b"\n", b""))
        with open(f"{file_path}/{file_name}.pk", "rb") as file: encoded_public_key = base58.b58decode(file.read().replace(b"\n", b""))
        
        self._secret_key = SecureBytes(encoded_secret_key)
        self._public_key = SecureBytes(encoded_public_key)
        return self


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
