from src.MyTypes import Bytes, Int


def hamming_distance(a: Bytes, b: Bytes) -> Int:
    """
    Calculate the Hamming distance between two hashes.
    @param a: The first hash.
    @param b: The second hash.
    @return: The Hamming distance.
    """

    # Ensure the hashes are the same length
    assert len(a) == len(b), "Hashes must be the same length"

    # Calculate the Hamming distance
    return sum([a_ != b_ for a_, b_ in zip(a, b)])
