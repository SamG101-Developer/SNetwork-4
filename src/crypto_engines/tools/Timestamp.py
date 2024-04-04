import time
from dataclasses import dataclass

from src.MyTypes import Bool, Int


@dataclass(kw_only=True)
class Tolerance:
    in_tolerance: Bool
    out_by: Int


class Timestamp:
    """
    The Timestamp class is used to generate and compare timestamps. Timestamps are used to ensure that messages are not
    replayed.
    """

    TOLERANCE = 10_000_000_000  # 10 seconds

    @staticmethod
    def current_time_bytes() -> bytes:
        # Get the current time in nanoseconds and return it as a bytes object.
        current_time = time.time_ns()
        return current_time.to_bytes(8, "big")

    @staticmethod
    def in_tolerance(t1: bytes, t2: bytes):
        # Convert the timestamps to integers and check if the difference is within the tolerance.
        t1 = int.from_bytes(t1, "big")
        t2 = int.from_bytes(t2, "big")
        return Tolerance(in_tolerance=t1 - t2 < Timestamp.TOLERANCE, out_by=t1 - t2)
