from __future__ import annotations
from dataclasses import dataclass
import socket

from crypto_engines.keys.key_pair import KeyPair, KEMKeyPair
from my_types import Bool, Bytes, Int, List, Optional, Str, Tuple


@dataclass(kw_only=True)
class ControlConnectionRouteNode:
    connection_token: ConnectionToken
    ephemeral_key_pair: Optional[KeyPair]
    shared_secret: Optional[KEMKeyPair]


@dataclass(kw_only=True)
class ControlConnectionRoute:
    route: List[ControlConnectionRouteNode]
    connection_token: ConnectionToken


@dataclass(kw_only=True)
class Address:
    ip: Str
    port: Int

    def socket_format(self) -> Tuple[Str, Int]:
        return self.ip, self.port

    @staticmethod
    def me() -> Address:
        return Address(ip=socket.gethostbyname(socket.gethostname()), port=12345)

    def __hash__(self):
        from hashlib import md5
        return int(md5(self.ip.encode()).hexdigest(), 16) % 2**64

    def __eq__(self, other) -> Bool:
        return self.ip == other.ip and self.port == other.port


@dataclass(kw_only=True)
class ConnectionToken:
    token: Bytes
    address: Address

    def __hash__(self):
        return (hash(self.token) * hash(self.address)) % 2**64


__all__ = ["ControlConnectionRoute", "ControlConnectionRouteNode", "Address", "ConnectionToken"]