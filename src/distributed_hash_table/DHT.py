from crypto_engines.tools.secure_bytes import SecureBytes
from my_types import Str, List
import base58, json, random


class NodeNotInNetworkException(Exception):
    pass


class DHT:
    DIRECTORY_NODES = {"192.168.1.49": b""}

    @staticmethod
    def get_static_public_key(address: Str) -> SecureBytes:
        cache = json.load(open("./_cache/dht_cache.json"))
        public_key = [node["key"] for node in cache if base58.b58decode(node["id"]).decode() == address]
        if not public_key:
            raise NodeNotInNetworkException

        public_key = base58.b58decode(public_key[0].replace("\n", ""))
        return SecureBytes(public_key)

    @staticmethod
    def get_random_node(block_list: List[Str]) -> Str:
        block_list = [base58.b58encode(node.encode()).decode() for node in block_list]
        cache = [entry["id"] for entry in json.load(open("./_cache/dht_cache.json"))]
        cache = list(set(cache) - set(block_list))
        random_id = random.choices(cache, k=1)[0]
        random_id = base58.b58decode(random_id).decode()
        return random_id

    @staticmethod
    def get_random_directory_node() -> Str:
        return random.choice(list(DHT.DIRECTORY_NODES.keys()))
