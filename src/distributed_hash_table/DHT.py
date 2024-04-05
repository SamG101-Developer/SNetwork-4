from threading import Lock
import json, random

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_der_public_key, Encoding, PublicFormat

from src.crypto_engines.crypto.Hashing import Hashing
from src.MyTypes import Str, List, Bytes, Dict, Optional


DIR_PUB_KEY = b"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApcf/R/EDoTdaEiu2i7iS
PpM2qeqtjQn7tmi4S3Qxyr9pM3qzIukISbbgiKv8Y0P5FtkZCOzUwQjwaN/3IFts
2OLVjpBu6Mv7M5Tq26JwoJP9oHW9P9AfYgW1l7rqR6osm30LWWOzVls6WplEXX2V
tsEFdceYe9YS0/HmSRyItXPqFcHuFvXNzsIyostgE9iSTGnHVlWriIEk94fsUw5J
5+n7gxdSQ03HxRPmv664esWdT7W8ZJKkg9JlWvy4hoxZS+dwhBLxe/8WUBZSVnCu
jFzwVYnAHugc3O1LsSYug4UBnClhMvVTuiXedjve/TcNFwX/lPgQj2wxgjwx6VwK
XQIDAQAB
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
        # Check cached directory nodes.
        if address in DHT.DIRECTORY_NODES.keys():
            return DHT.DIRECTORY_NODES[address]

        # Lock the cache file and read the json node cache.
        with DHT.LOCK:
            cache = json.load(open("./_cache/dht_cache.json"))

        # Check if the node is in the cache - todo: do against ID not IP?
        public_key = [node["key"] for node in cache if node["ip"] == address]
        if not public_key:
            if not silent:
                raise NodeNotInNetworkException(f"Node with IP {address} is not in the network.")
            return None

        # Load the public key from the cache.
        public_key = load_der_public_key(bytes.fromhex(public_key[0]))
        return public_key

    @staticmethod
    def get_id(address: str, silent: bool = False) -> bytes:
        # Get the public key of the node.
        public_key = DHT.get_static_public_key(address, silent)

        # Hash the public key to get the node ID.
        if public_key:
            node_id = Hashing.hash(public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
            return node_id

        # Return an empty byte string if the node is not in the network.
        return b""

    @staticmethod
    def get_fixed_node(ip: Str) -> Dict[Str, Str]:
        with DHT.LOCK:
            cache = json.load(open("./_cache/dht_cache.json"))

        fixed_node = [node for node in cache if node["ip"] == ip]
        if fixed_node:
            fixed_node = fixed_node[0]
            fixed_node["id" ] = bytes.fromhex(fixed_node["id"])
            fixed_node["key"] = bytes.fromhex(fixed_node["key"])
            return fixed_node

        return {}

    @staticmethod
    def get_random_node(block_list: List[Str] = None) -> Dict[Str, Str]:
        block_list = block_list or []
        with DHT.LOCK:
            cache = json.load(open("./_cache/dht_cache.json"))

        valid_ips = [node for node in cache if node["ip"] not in block_list]
        random_node = random.choice(valid_ips) if valid_ips else None

        if random_node:
            random_node["id" ] = bytes.fromhex(random_node["id"])
            random_node["key"] = bytes.fromhex(random_node["key"])

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
            cache.append({"id": node_id.hex(), "key": node_public_key.hex(), "ip": ip_address})
            json.dump(cache, open("./_cache/dht_cache.json", "w"))
