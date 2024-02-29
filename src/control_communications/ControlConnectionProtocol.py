from enum import Enum


class ControlConnectionProtocol(Enum):
    CONN_REQ     = 0b0000  # Request a connection
    CONN_ACC     = 0b0001  # Accept a connection request
    CONN_REJ     = 0b0011  # Reject a connection request
    CONN_CLS     = 0b0100  # Close a connection
    CONN_ERR     = 0b0101  # Error in connection
    CONN_FWD     = 0b0110  # Forward a connection command
    CONN_EXT     = 0b0111  # Extend a connection
    CONN_SEC     = 0b1000  # E2E connection is secured
    CONN_EXT_ACC = 0b1001  # Acknowledge an extended connection
    CONN_EXT_REJ = 0b1010  # Reject an extended connection
    CONN_PKT_KEM = 0b1011  # Packet key: send pub key for KEM
    CONN_PKT_KEY = 0b1100  # Packet key: send KEM-wrapped key
    CONN_PKT_ACK = 0b1101  # Packet key: acknowledge key receipt


__all__ = ["ControlConnectionProtocol"]
