from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat, PublicFormat, NoEncryption

from src.MyTypes import Optional


class KeyPair:
    _secret_key: Optional[RSAPrivateKey]
    _public_key: Optional[RSAPublicKey]

    def __init__(self, secret_key: Optional[RSAPrivateKey] = None, public_key: Optional[RSAPublicKey] = None) -> None:
        self._secret_key = secret_key
        self._public_key = public_key

    @property
    def secret_key(self) -> Optional[RSAPrivateKey]:
        assert self._secret_key is not None
        return self._secret_key

    @property
    def public_key(self) -> Optional[RSAPublicKey]:
        assert self._public_key is not None
        return self._public_key

    def export(self, file_path: str, file_name: str) -> KeyPair:
        secret_pem = self.secret_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
        public_pem = self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        open(f"{file_path}/{file_name}_sec.pem", "wb").write(secret_pem)
        open(f"{file_path}/{file_name}_pub.pem", "wb").write(public_pem)
        return self

    def import_(self, file_path: str, file_name: str) -> KeyPair:
        self._secret_key = load_pem_private_key(open(f"{file_path}/{file_name}_sec.pem", "rb").read(), password=None)
        self._public_key = load_pem_public_key(open(f"{file_path}/{file_name}_pub.pem", "rb").read())
        return self

    def both(self) -> tuple[RSAPrivateKey, RSAPublicKey]:
        return self.secret_key, self.public_key


class KEMKeyPair:
    _encapsulated_key: bytes
    _decapsulated_key: bytes

    def __init__(self, encapsulated_key: bytes, decapsulated_key: bytes) -> None:
        self._encapsulated_key = encapsulated_key
        self._decapsulated_key = decapsulated_key

    @property
    def encapsulated_key(self) -> bytes:
        return self._encapsulated_key

    @property
    def decapsulated_key(self) -> bytes:
        return self._decapsulated_key
