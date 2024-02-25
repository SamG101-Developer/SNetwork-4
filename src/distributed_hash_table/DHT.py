from src.crypto_engines.tools.secure_bytes import SecureBytes
from src.my_types import Str
import json, random


class NodeNotInNetworkException(Exception):
    pass


class DHT:
    @staticmethod
    def get_static_public_key(address: Str) -> SecureBytes:
        cache = json.load(open("./_cache/dht_cache.json"))
        public_key = [node["pub_key"] for node in cache if node["id"] == address]
        if not public_key:
            raise NodeNotInNetworkException

        return SecureBytes(public_key[0])

    @staticmethod
    def get_random_node() -> Str:
        cache = json.load(open("./_cache/dht_cache.json"))
        return random.choices(cache, k=1)[0]["id"]
