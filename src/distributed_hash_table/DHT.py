from threading import Lock
import json, logging, random

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat

from src.crypto_engines.crypto.Hashing import Hashing
from src.MyTypes import Str, List, Bytes, Dict, Optional


DIR_PUB_KEY = b"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyUBc1wWhvur15VDQXDOd
JARbQojA1UC+yvH+pQG5juTUCM2j0KO1IsPqbx4DJ03ID52y7S27pcJ4vBTNBUjL
2EahrFCffXwwMMfQkH7Wq0JOi/weTqkouQxPHTLCFXz60GhjkdGfFnejX2fGQQ8p
oUSO8F+qVPInKfaoLkUrhkZQl1XoQBe//kc9b4A0pCTb3qWLMdNjYVIgcqEG23Ku
2TtrNzO8bQsGfCTOje7ZWHvpJycEI7GN9FnrecMAz9nrxr3f9yJkvqUWHnC0YJaO
sF5iEYEGjI9P1bWnbtBAESf2jpHy1f41P5FOSAqxFAplWDUTOdTlTEVLTPIj3/5Q
2wIDAQAB
-----END PUBLIC KEY-----
"""


class NodeNotInNetworkException(Exception):
    pass


class DHT:
    LOCK = Lock()

    DIRECTORY_NODES = {
        "192.168.0.90": load_pem_public_key(DIR_PUB_KEY),
    }

    @staticmethod
    def get_static_public_key(address: Str, silent: bool = False) -> Optional[RSAPublicKey]:
        if address in DHT.DIRECTORY_NODES.keys():
            return DHT.DIRECTORY_NODES[address]

        with DHT.LOCK:
            cache = json.load(open("./_cache/dht_cache.json"))

        public_key = [node["key"] for node in cache if node["ip"] == address]
        if not public_key:
            if not silent:
                raise NodeNotInNetworkException
            return None

        public_key = load_pem_public_key(public_key[0])
        return public_key

    @staticmethod
    def get_id(address: str, silent: bool = False) -> bytes:
        public_key = DHT.get_static_public_key(address, silent)
        if public_key:
            node_id = Hashing.hash(public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
            return node_id
        return b""

    @staticmethod
    def get_random_node(block_list: List[Str] = None) -> Dict[Str, Str]:
        block_list = block_list or []
        with DHT.LOCK:
            cache = json.load(open("./_cache/dht_cache.json"))

        valid_ips = [node for node in cache if node["ip"] not in block_list]
        random_node = random.choice(valid_ips) if valid_ips else None

        if random_node:
            random_node["id" ] = random_node["id"]
            random_node["key"] = random_node["key"]

        return random_node

    @staticmethod
    def total_nodes_known(block_list: List[Str] = None) -> int:
        block_list = block_list or []
        with DHT.LOCK:
            known_nodes = json.load(open("./_cache/dht_cache.json"))
        valid_ips = [node for node in known_nodes if node["ip"] not in block_list]
        return len(valid_ips)

    @staticmethod
    def get_random_directory_node() -> Str:
        return random.choice(list(DHT.DIRECTORY_NODES.keys()))

    @staticmethod
    def cache_node_information(node_id: Bytes, node_public_key: Bytes, ip_address: Str) -> None:
        with DHT.LOCK:
            cache = json.load(open("./_cache/dht_cache.json"))
            cache.append({"id": node_id.decode(), "key": node_public_key.decode(), "ip": ip_address})
            json.dump(cache, open("./_cache/dht_cache.json", "w"))
