from crypto_engines.crypto.hashing import Hashing
from crypto_engines.tools.secure_bytes import SecureBytes
from my_types import Str, List, Bytes, Dict
import base58, json, random


class NodeNotInNetworkException(Exception):
    pass


class DHT:
    DIRECTORY_NODES = {
        "192.168.0.90": SecureBytes(base58.b58decode("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"))
    }

    @staticmethod
    def get_static_public_key(address: Str, silent: bool = False) -> SecureBytes:
        if address in DHT.DIRECTORY_NODES.keys():
            return DHT.DIRECTORY_NODES[address]

        cache = json.load(open("./_cache/dht_cache.json"))
        public_key = [node["key"] for node in cache if node["ip"] == address]
        if not public_key:
            if not silent:
                raise NodeNotInNetworkException
            return None

        public_key = base58.b58decode(public_key[-1].replace("\n", ""))
        return SecureBytes(public_key)

    @staticmethod
    def get_id(address: str, silent: bool = False) -> SecureBytes:
        public_key = DHT.get_static_public_key(address, silent)
        if public_key:
            node_id = Hashing.hash(public_key)
            return node_id

    @staticmethod
    def get_random_node(block_list: List[Str] = None) -> Dict[Str, Str]:
        block_list = block_list or []
        cache = json.load(open("./_cache/dht_cache.json"))

        valid_ips = [node for node in cache if node["ip"] not in block_list]
        random_node = random.choice(valid_ips) if valid_ips else None
        return random_node

    @staticmethod
    def total_nodes_known(block_list: List[Str] = None) -> int:
        block_list = block_list or []
        known_nodes = json.load(open("./_cache/dht_cache.json"))
        valid_ips = [node for node in known_nodes if node["ip"] not in block_list]
        return len(valid_ips)

    @staticmethod
    def get_random_directory_node() -> Str:
        return random.choice(list(DHT.DIRECTORY_NODES.keys()))

    @staticmethod
    def cache_node_information(node_id: Bytes, node_public_key: Bytes, ip_address: Str) -> None:
        cache = json.load(open("./_cache/dht_cache.json"))
        cache.append({"id": base58.b58encode(node_id).decode(), "key": base58.b58encode(node_public_key).decode(), "ip": ip_address})
        json.dump(cache, open("./_cache/dht_cache.json", "w"))
