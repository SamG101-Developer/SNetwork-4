from enum import Enum


# Interacting with other nodes
class ControlConnectionProtocol(Enum):
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

    DIR_REG     = 0b01110  # Register a new node to the directory node + first certificate
    DIR_CER_REQ = 0b01111  # Request a new time-updated certificate for a node from a directory node
    DIR_CER     = 0b10000  # Certificate for a node from a directory node
    DIR_LST_REQ = 0b10001  # Request a directory node for a list of nodes
    DIR_LST_RES = 0b10010  # Response to a list request

    DHT_EXH_REQ = 0b10011  # Request node certificate to prove on network
    DHT_EXH_RES = 0b10100  # Response to a certificate request
    DHT_EXH_ADR = 0b10101  # Exchange IP addresses with a node
    DHT_EXH_ACK = 0b10110  # Acknowledge an address exchange
    DHT_CLOSER_NODES_REQ = 0b11000  # Request closer nodes to a key
    DHT_CLOSER_NODES_RES = 0b11001  # Response to closer nodes request
    DHT_ADV = 0b11010  # Advertise a file to a node on the network
    DHT_SEND_BROKER_REQ = 0b10111  # Request a broker node for a file
    DHT_FILE_GET_FROM_BROKER = 0b11011  # Request a file from a broker node
    DHT_FILE_GET_FROM_SOURCE = 0b11100  # Request a file from the source node
    DHT_FILE_CONTENTS_TO_BROKER = 0b11101  # Send the contents of a file to a broker node
    DHT_FILE_CONTENTS_TO_CLIENT = 0b11110  # Send the contents of a file to a client node


__all__ = ["ControlConnectionProtocol"]
