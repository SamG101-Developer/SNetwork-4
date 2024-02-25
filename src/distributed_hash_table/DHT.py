from src.crypto_engines.tools.secure_bytes import SecureBytes
from src.my_types import Dict, Str
import json


class NodeNotInNetworkException(Exception):
    pass


class DHT:
    @staticmethod
    def get_static_public_key(address: Str) -> SecureBytes:
        cache = json.loads("./_cache/dht_cache")
        public_key = [node["pub_key"] for node in cache if node["id"] == address]
        if not public_key:
            raise NodeNotInNetworkException

        return SecureBytes(public_key[0])
