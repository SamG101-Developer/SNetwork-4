from enum import Enum


# Base class for all connection protocols
class ConnectionProtocol(Enum):
    ...


# Interacting with other nodes
class ControlConnectionProtocol(ConnectionProtocol):
    CONN_REQ     = 0b00000  # Request a connection
    CONN_ACC     = 0b00001  # Accept a connection request
    CONN_REJ     = 0b00011  # Reject a connection request
    CONN_CLS     = 0b00100  # Close a connection
    CONN_ERR     = 0b00101  # Error in connection
    CONN_FWD     = 0b00110  # Forward a connection command
    CONN_EXT     = 0b00111  # Extend a connection
    CONN_SEC     = 0b01000  # E2E connection is secured
    CONN_EXT_ACC = 0b01001  # Acknowledge an extended connection
    CONN_EXT_REJ = 0b01010  # Reject an extended connection
    CONN_PKT_KEM = 0b01011  # Packet key: send pub key for KEM
    CONN_PKT_KEY = 0b01100  # Packet key: send KEM-wrapped key
    CONN_PKT_ACK = 0b01101  # Packet key: acknowledge key receipt


# Interacting with the directory nodes
class DirectoryConnectionProtocol(ConnectionProtocol):
    DIR_REG     = 0b01110  # Register a new node to the directory node + first certificate
    DIR_CER_REQ = 0b01111  # Request a new time-updated certificate for a node from a directory node
    DIR_CER     = 0b10000  # Certificate for a node from a directory node
    DIR_LST_REQ = 0b10001  # Request a directory node for a list of nodes
    DIR_LST_RES = 0b10010  # Response to a list request


__all__ = ["ConnectionProtocol", "ControlConnectionProtocol", "DirectoryConnectionProtocol"]
