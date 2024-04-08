from src.MyTypes import Bytes, Int


def hash_distance(a: Bytes, b: Bytes) -> Int:
    """
    Determine the distance between two hashes, by taking the absolute difference between them.
    @param a:
    @param b:
    @return:
    """

    a_int = int.from_bytes(a, "big")
    b_int = int.from_bytes(b, "big")
    return abs(a_int - b_int)
