from crypto_engines.tools.secure_bytes import SecureBytes
import time


class Timestamp:
    """
    The Timestamp class is used to generate and compare timestamps. Timestamps are used to ensure that messages are not
    replayed.
    """

    TOLERANCE = 50_000_000

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
        return t1 - t2 < Timestamp.TOLERANCE
