from crypto_engines.tools.secure_bytes import SecureBytes
from my_types import Str, List, Bytes
import base58, json, random


class NodeNotInNetworkException(Exception):
    pass


class DHT:
    DIRECTORY_NODES = {"192.168.1.106": b'<\n\xeb\x88pT\xda\x94\xd6\x95\xa1~-\x8c\xd3\xc3\xfa\xf0(\xf0M\x1ap\xda=\xc4-@\xdb\xe2\xa5N\xdf;zK|\xba\x0b\xfb:\xabN\xc5\x01\xb9\xc9\xbb\xf9r\x9c\xfb\x96\xff\xd1o\x10;\xb5P\xa3\xf2`\xefU[\xe9W\xe3+\x8cI&\xf4\xbc[\x1dYQ\x95\xfb\xc0\xca\xd6\xb1\x9b\xacO\x85\xd4\xfa\xaa\xfd\xb2~\x90\xe0d\xd3Bt\xfe\x85~\xfa\xca\'\xf8\x93\xdc\r.\xe9\x08\xef\xa8|\x9e\t\xddz\rV,\xc7q\x11\xc5n\xf54\xf63,\xd2\xa0\xc5i\xd3\xb5\n~\x85\xc36\xc2\xf2\xc2IDCo\x84\x84\xb5\xd6\x1ex\x9e_%\x19\\%<\xf5\x98D*!QC&YlX4\x1f.\xcc\xa0\xba\x10QE\x16\xa7q\xfa\xee\x04\\.&?\xf7\xfc/\x16I\xab\x17\x82\x16\x05]p\xbc\xb5\x98\xba\xc3s*\xdc)d;@\xe1c\xbbR$c\x1cC\xca{>\xc8\x16t\xa3~\xca\xbc\xb5R\xe7\xf8z\xa7\xb8\xdd\xc1\xf9\xac\x96%\xca\xd4\x08\xb0\x94V\x0b\xd63\x942\xbbj\xe7&O\xbb\xba\x1b\r\xb5\x04\xf1c\x12\x91\xa9\xb0\xc2\x1d@\x87/P;&G\xff\xee\xa6\x99\x19BH\xc3C\xf0ET\xe9\x179\x17^?i\x03|\xde\xe2a\x8e\xbb\xef3\x92\x95\xfc[H\xc3\x92kGa)P\xa3>?\xd5^\xc6\xe9\xf9oV4\x89\x08N`\xe2\xe6\x18\x95\xe7\xe5"\n\x13\x90j\x11\xf6\x0e\x9cz\x92\'\x95)\x90\xa2\xca\xf3r\x9e:\x7f\xb2S\xa5\x84\xb5\x08\xe6\xa7>n\xfc9\xf5\x1eb`\xd2\xc0\x16\\y\x85\xbc\xd9 >\x8b6\xbb\xb1`+\xfdm\x87o\x8a\xcd\x08\xa1Ei\x18\xe8\x8f\xad\xbdS\x14\x1f\xbdT$\xa8V\xbf\x82\xd8\xf7\xf8\xccM/J\x169D\xd5\xec~\xbd6\xd38\xa8!\xeb\x92\x1c\xfc\xe2Z\xee6\x85\xceR\xe2\xbe:\xb8\xb0\t\xc9\x1bE\x87\xf5\xa9\x95\')\x17\xad\xa6\x96\x9e;\xdd\x8a\x9e\xe3\xeec\x7f\x16\x84\x91_\xab\xfe\x1eN\xea\xe0\x89ow3\xd5\x99\xa3\xdb\x1b\x10\xea&\xb6\xfa\x95\xe4I\xbe%\xf8i\x1e\xad\xe8dgL\xae\xfbw\xe7\xca_\x07y\xaf\xc0\xa4\xf9.&\x1a\xb8!\x0eP\x86H\x0cz\x8fX\xaa9b\x91\xad.^U\xc1\xcb0\xa2\n\xad\xb1\xf9\x00\xd8[\xe9V\xa6\xd5EK\x06\xdeC[\xb0\xa7\x93f\xb7>Dg\\\xcee:\x18=d\xa2\xc5\xcf\xb8\xaa\xe3.\xfbD\xa0F%\xbc,2P\xdd\x9a\xbb`\xd4\x822\x06\x8c\x97\xc1 \xf8\xbe\x1c\xfbt7\\;1\xd9\xfe"z\xab\x7fy\xf0g+\xa3\xd1\xd5?}\x91`\x16\xe6v\xbd^*\xfe\xb7\x9b1\x86\xb3j\xe6\xaeIt\xc0#\xf1\x04\xdc\r\xbcS\x9b\x08BD\xf1\x8el!\x8aD\xba\x1cu\x8d\xe8{+\x17\xd9\xa4\xdcI\x9c\x82I\xde\x13\xff\x83=\x93\x919k\\\xacmY5\xa6\x9b\xb6\xac\xf4Aw\xe0Wb\xa4\x03<\x16\x06\xb6pg|j\xc6\xadZ9\xfa\xdb\xdf2\xaf\x94\xbf\xe7\x01X\x0c\x8f\x14\x01\x8b\\\xb5\xc9\x07\xa9\xafw\x1d\x93\xc4wp\xcek\x9a\xe5t\xa3v\x81W\xba\x15\xae\xc9q\xa4e\xb3[\x13\x85\x06\xd4m\x9f\xc6E\x9b\xdc\xd87\xca\xb8\x8e+|\x14V=W,@B_\xf3\xd2?KM`H2\x07\xcf%\x1b\x18l\xc5K\x9d\x7f-&\xb5\x0e\x85/\x92\\\xbd\xd5\xb9\x11\xea)n6\xa2\x9f\x065\x1d\x94\xaa\x90\x95\xe3\x8b\xd8`\xf8\x8c\x8a\x10ct\x17\xbb\x87\xe5\xa9\\\xa5\nv\xd5_-$Q\xec\x10\r\xdd\n\x04\xac\xc8.\x06\x8fT\x0eI\xfa\xa4d\x97\xe1x\x9b\xc26l\xecb1\x87\xbc\xf8t\xcd\x1b\xae\r;\xa4|+:\xcb\x06\x89\xdf\x9c\x8d<]\xc5\x8b\xe1\n\xc7\xe3]\x96t\\\xfe\x11V\x1a\x9c\'\x9a\n\xbe\x06\xa8LM\xf1\x95\x9a\xf8\xc2\x90\xb1\x89\xe1(\xf9:]\x99y\xd3\x0f\xf6\xe7\xf3\xed\xbc\xb4\xed\xb0m\x9dV"\xe5q5\xc1\x1b\xa5x\xe50T\xe8o\xca\x9c\x95\x01\xd2\x02\xc1\xe4\xe4\xab\x82q\xdeRg\xf9\xf7]\xb0\x9b\xdc\xfb\x8c\xf8\x9f\xfbE\xb6\xb2=X\x12LaF\xf9\x0f2\xb3\x08\x955\x86oI\xc94Lx\xd9ry\x9d\xdb\x95<\xea\xf1\x0c\xda\r\xd0\xfc\xbb\xbc\xfb\\\x1d\xdd\xfa[2\xe2g\xd0"\x86\xd7\x90\xf7\\Nq\xb7\xc2\x01\xa0p\xa7@\xf8]~>\x1b\xce5\xe1J]K\xa6\nY\xa8\x08\xb6\xd1\xd5\x8a,\xdf\n\xc4?\x93\xdeuN\x7fY\xa8I\xa9\x9e\x7f%\x92Z7*\x12i\x06[1]\x93\x03\xa88l\xd1\xb1uP2FDi4v\xcf\xff\xe03\x1dz\x8c\x1d" \xe1\xbcs\x8aN\xdci\x96A\xac\x90@s.b\xdc7~z\x92\x90\x97g\nr\'8\xe5\xc8\xd6\xb6\xa8\xd9t\xe9\xa0 \xad\xb8\xf6B\xe0\x18e\xef\x85\xfe\x00\xd9]\xc4F\x80\x17*.\xa1fn*N\xe7?\xf7\x15\x1b\x0f\x9b\xa2\x0f\xa3G\xcf(M\x00\xee(\x0e\xa2C\xba\xe6,\xe4\xb96\x97r\r\x1c\xba`\x91\x12k\x18Of\xf4\x9d6\xe9\xaf4\xe1(\xd7\\\xbf\xe6V\xe6n\x03\xb9\xf8\xec\x7fy\xfa\x1c\xe7}\x1a\xb0\x85UR\xf5\x15;\xe3\x18\xf5\xdb\xd7\xe0\xad\xed\x9dM51\xf1\xd3\xa5\xf4\xf7\xf6\xda\xd83g\x1a\x16>\xc4\x05\xb8\xeb`A\x80\x1f\xa2\x08\xed\x06\x7f\n\xde~1\xff\x96\xe8 \xbf\xf4\x9b \xec\x08e\x0eH\xc1\x00\xef\xc2f\xc2\xf2\x98k\xb3\x9cY\x04\xc0\xdc\xad\x84\x1etC\xaf1\xa6M\x9450\xac#V\xf6\xc6\x88\x8e\xef\xb5\x84\x0f\xa14\xf3+e\xb8\xdd|\x1d)\xe3\xeb\x93<\xc5{\xf8\xfe\xcaj\x10[\xdc\x08p\xe6\xaf\xec\x0e1\xda\xbeser\xd8\xe3G\xa1\x9cf/\xcc\xa1\xc5\x96y4\xc1\xb8\x16\x83\x17\x17*\xb2\xd5\xea\xa9\xb4]\xddcP3\x84"\xee^\xb4\x8a\x8e\x8b\x03\xf3s\x1e\xcbsH{\xbcb\xf7w\xb6\x90\x18\xb7dw\x8c\xfa\xf8\x1b.\xb2\xc3\xee\x86\x117\xb15SsS\xd2\x8d\x9fo\x11&\xadz\xc9D\xa8E\xaf`\xb1P\x07Q)\xdbcP\xfd\x16\xe2\xd0\x8c~\x9a}\x0e\x83\xc5OAVF\x02H]\xd9\xb0\x8cT;3\x1cMS\x1f\xa4\xb6}\xe7\xdc\x8e>/\xf0\x19\x0e=\x85\xf5\xca\xd4\x89\x1d\x9cv\xbfo\xbe&\x12/\xd7\xa1PK\xf6\x81\xab\xc9\x9dLH\xcf\x9a,(\xe2Y\x8ca\xc1\x82\x80\xb9\x8c\x11\xf3Ws\xd2U\x10\xde\xc1EQ\x8fk\x90\xd4\n#[1\x98\xcc\xd2\x82\xcc\xca\xa1\x0b\x9dF\xe8S3+\xc7>6\xce\x18\x05\xd4\xae7\xa5\r\xc7\x86q\x86\x82V;_\x03\xf3^\xd8t\x1a\xfb\xbe\xd5uQd\xc2"\xac/Z\xb9\x99\xb8\xca\xacLA\xf0\xdb\xb8aA\xec0\xd8\xc5\x18\x95e7e\xee\xbc\xd2@;FY\x16\x9d6\xe9XC\x1e\xd5~\xe06I@\x92\x1f8?\xd8\xb6\xcd\xa8;\xc4\xd9\n\xcb\xf01O\xc6O\xe8FF\xfc\xd5\xa7\xed\xc8@\xf9\xe8|\x7f\xe4\xd6\x0e\xb9\xd6\x0eoy7\x01}\x10\x12\x17\xafe\xdf\x9ft?D\xea\xe6t\xb3\x89\xad-\xeb0)#\xb5\xfe}\x9b\x1b\x14\xea0\x06\xa2\x01'}

    @staticmethod
    def get_static_public_key(address: Str) -> SecureBytes:
        if address in DHT.DIRECTORY_NODES.keys():
            return SecureBytes(DHT.DIRECTORY_NODES[address])

        cache = json.load(open("./_cache/dht_cache.json"))
        public_key = [node["key"] for node in cache if node["ip"] == address]
        if not public_key:
            raise NodeNotInNetworkException

        public_key = base58.b58decode(public_key[0].replace("\n", ""))
        return SecureBytes(public_key)

    @staticmethod
    def get_random_node(block_list: List[Str]) -> Str:
        cache = [entry["ip"] for entry in json.load(open("./_cache/dht_cache.json"))]
        cache = list(set(cache) - set(block_list))
        random_id = random.choices(cache, k=1)[0]
        random_id = base58.b58decode(random_id).decode()
        return random_id

    @staticmethod
    def get_random_directory_node() -> Str:
        return random.choice(list(DHT.DIRECTORY_NODES.keys()))

    @staticmethod
    def cache_node_information(node_id: Bytes, node_public_key: Bytes, ip_address: Str) -> None:
        cache = json.load(open("./_cache/dht_cache.json"))
        cache.append({"id": base58.b58encode(node_id).decode(), "key": base58.b58encode(node_public_key).decode(), "ip": ip_address})
        json.dump(cache, open("./_cache/dht_cache.json", "w"))
