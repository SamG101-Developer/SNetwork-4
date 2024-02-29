from enum import Enum


class ControlConnectionProtocol(Enum):
    CONN_REQ     = 0b0000  # Request a connection
    CONN_ACC     = 0b0001  # Accept a connection request
    CONN_REJ     = 0b0011  # Reject a connection request
    CONN_CLS     = 0b0011  # Close a connection
    CONN_ERR     = 0b0100  # Error in connection
    CONN_FWD     = 0b0101  # Forward a connection command
    CONN_EXT     = 0b0110  # Extend a connection
    CONN_EXT_ACC = 0b0111  # Acknowledge an extended connection
    CONN_EXT_REJ = 0b1000  # Reject an extended connection
    CONN_PKT_KEM = 0b1001  # Packet key: send pub key for KEM
    CONN_PKT_KEY = 0b1010  # Packet key: send KEM-wrapped key
    CONN_PKT_ACK = 0b1011  # Packet key: acknowledge key receipt


__all__ = ["ControlConnectionProtocol"]
