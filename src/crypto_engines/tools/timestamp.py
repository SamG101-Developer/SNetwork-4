from crypto_engines.tools.secure_bytes import SecureBytes
from my_types import Bool, Int

from dataclasses import dataclass
import time


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
    def current_time_bytes() -> SecureBytes:
        # Get the current time in nanoseconds and return it as a SecureBytes object.
        current_time = time.time_ns()
        return SecureBytes.from_int(current_time)

    @staticmethod
    def in_tolerance(t1: SecureBytes, t2: SecureBytes):
        # Convert the timestamps to integers and check if the difference is within the tolerance.
        t1 = t1.to_int()
        t2 = t2.to_int()
        return Tolerance(in_tolerance=t1 - t2 < Timestamp.TOLERANCE, out_by=t1 - t2)
