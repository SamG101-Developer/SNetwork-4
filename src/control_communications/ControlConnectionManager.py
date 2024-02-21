from socket import socket as Socket, AF_INET, SOCK_DGRAM
from threading import Thread, Lock
from enum import Enum
from dataclasses import dataclass
import pickle
import threading

from src.crypto_engines.crypto.digital_signing import DigitalSigning, SignedMessage
from src.crypto_engines.crypto.key_encapsulation import KEM
from src.crypto_engines.crypto.symmetric_encryption import SymmetricEncryption
from src.crypto_engines.keys.key_pair import KeyPair
from src.crypto_engines.tools.secure_bytes import SecureBytes
from src.types import Bytes, Tuple, Str, Int, List, Dict, Optional


type Address = Tuple[Str, Int]
type ConnectionToken = Tuple[Bytes, Address]


class ControlConnectionState(Enum):
    WAITING_FOR_ACK = 0
    CONNECTED = 1


class ControlConnectionProtocol(Enum):
    CONN_REQ = 0b000  # Request a connection
    CONN_ACC = 0b001  # Accept a connection request
    CONN_REJ = 0b011  # Reject a connection request
    CONN_CLS = 0b011  # Close a connection
    CONN_ERR = 0b100  # Error in connection
    CONN_FWD = 0b101  # Forward a connection command
    CONN_EXT = 0b110  # Extend a connection


@dataclass
class ControlConnectionConversationInfo:
    state: ControlConnectionState
    their_static_public_key: SecureBytes
    shared_secret: Optional[SecureBytes]
    my_ephemeral_secret_key: Optional[SecureBytes]


def ReplayErrorBackToUser(function):
    def outer(error_command):
        def inner(self, addr, conversation_token, data):
            try:
                function(self, addr, data)
            except Exception as e:
                self._send_message(addr, conversation_token, error_command, str(e))
        return inner
    return outer


class ControlConnectionManager:
    _udp_server: Socket
    _msg_threads: List[Thread]
    _conversations: Dict[ConnectionToken, ControlConnectionConversationInfo]
    _mutex: Lock

    def __init__(self):
        # Setup the socket of the control connection manager
        self._udp_server = Socket(AF_INET, SOCK_DGRAM)
        self._msg_threads = []
        self._conversations = {}
        self._mutex = Lock()
        self._setup_socket()

    def _setup_socket(self) -> None:
        # Bind a UDP socket for incoming commands to this node
        self._udp_server.bind(("", 12345))

        # For each message received, handle it in a new thread
        while True:
            self._recv_message()

    def _recv_message(self) -> None:
        # Get the data and address from the udp socket, and parse the message into a command and data. Split the data
        # into the connection token and the rest of the data.
        data, addr = self._udp_server.recvfrom(1024)
        command, data = self._parse_message(data)
        connection_token, data = data[:32], data[32:]

        # Decrypt the data if a shared secret exists (only won't when initiating a connection).
        conversation_id = (connection_token, addr)
        if self._conversations[conversation_id].shared_secret:
            symmetric_key = self._conversations[conversation_id].shared_secret
            data = SecureBytes(data)
            data = SymmetricEncryption.decrypt(data, symmetric_key).raw

        # Create a new thread to handle the message, and add it to the list of message threads.
        msg_thread = Thread(target=self._handle_message, args=(addr, command, connection_token, data))
        msg_thread.start()
        self._msg_threads.append(msg_thread)

    def _parse_message(self, data: Bytes) -> Tuple[ControlConnectionProtocol, Bytes]:
        # Parse the message into a command and data
        command = ControlConnectionProtocol(data[0])
        data = data[1:]
        return command, data

    def _handle_message(self, addr: Address, command: ControlConnectionProtocol, connection_token: Bytes, data: Bytes) -> None:
        waiting_for_ack = self._waiting_for_ack_from(addr, connection_token)
        connected = self._is_connected_to(addr, connection_token)

        match command:
            case ControlConnectionProtocol.CONN_REQ:
                self._mutex.acquire()
                self._handle_request_to_connect(addr, connection_token, data)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_ACC if waiting_for_ack:
                self._mutex.acquire()
                self._handle_accept_connection(addr, connection_token, data)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_REJ if waiting_for_ack:
                self._mutex.acquire()
                self._handle_reject_connection(addr, connection_token, data)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_CLS if waiting_for_ack or connected:
                self._mutex.acquire()
                self._cleanup_connection(addr)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_EXT if connected:
                self._mutex.acquire()
                self._handle_extend_connection(addr, connection_token, data)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_FWD:
                self._mutex.acquire()
                self._forward_message(addr, data)
                self._mutex.release()

            case _:
                pass

        # End this handler thread, and remove it from the list of message threads.
        current_thread = threading.current_thread()
        self._msg_threads.remove(current_thread)
        current_thread.join()

    @ReplayErrorBackToUser(ControlConnectionProtocol.CONN_REJ)
    def _handle_request_to_connect(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        Handle a request from a Node to connect to this Node, and establish an encrypted tunnel for UDP traffic. The
        request will always come from a node that will be behind this node in the route.
        :param addr: Address of a node requesting this node to partake in a connection.
        :param data: Accompanying data with the request.
        """

        # Get their static public key from the DHT, and the parse the signed message.
        my_static_public_key, my_static_private_key = KeyPair().import_("./_keys/me", "static").both()
        their_static_public_key = DHT.get_static_public_key(addr)
        their_signed_ephemeral_public_key: SignedMessage = pickle.loads(data)

        # Verify the signature of the ephemeral public key being sent from the requesting node.
        DigitalSigning.verify(
            their_static_public_key=their_static_public_key,
            signed_message=their_signed_ephemeral_public_key,
            my_id=my_static_public_key)

        # Create a shared secret with a KEM, using their ephemeral public key, and sign it.
        their_ephemeral_public_key = their_signed_ephemeral_public_key.message
        kem_wrapped_shared_secret  = KEM.kem_wrap(their_ephemeral_public_key)
        signed_kem_wrapped_shared_secret = DigitalSigning.sign(
            my_static_private_key=my_static_private_key,
            message=kem_wrapped_shared_secret.encapsulated_key,
            their_id=their_static_public_key)

        # Send the signed KEM wrapped shared secret to the requesting node.
        sending_data = pickle.dumps(signed_kem_wrapped_shared_secret)
        self._send_message(addr, connection_token, ControlConnectionProtocol.CONN_ACC, sending_data)

        # Save the connection information for the requesting node.
        conversation_id = (connection_token, addr)
        self._conversations[conversation_id] = ControlConnectionConversationInfo(
            state=ControlConnectionState.CONNECTED,
            their_static_public_key=their_static_public_key,
            shared_secret=kem_wrapped_shared_secret.decapsulated_key,
            my_ephemeral_secret_key=None)

    @ReplayErrorBackToUser
    def _handle_accept_connection(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        Handle an acceptance from a Node Y to connect to this Node X. Node X will have already sent a CONN_REQ to NODE
        Y; thus it stands that Node Y will always come after Node X in the route.
        :param addr:
        :return:
        """

        # Get the signed KEM wrapped shared secret from the data, and verify the signature.
        my_static_public_key = KeyPair().import_("./_keys/me", "static").public_key
        their_static_public_key = DHT.get_static_public_key(addr)
        signed_kem_wrapped_shared_secret: SignedMessage = pickle.loads(data)

        # Verify the signature of the KEM wrapped shared secret being sent from the accepting node.
        DigitalSigning.verify(
            their_static_public_key=their_static_public_key,
            signed_message=signed_kem_wrapped_shared_secret,
            my_id=my_static_public_key)

        # Save the connection information for the accepting node.
        conversation_id = (connection_token, addr)
        my_ephemeral_secret_key = self._conversations[conversation_id].my_ephemeral_secret_key
        self._conversations[conversation_id] = ControlConnectionConversationInfo(
            state=ControlConnectionState.CONNECTED,
            their_static_public_key=their_static_public_key,
            shared_secret=KEM.kem_unwrap(my_ephemeral_secret_key, signed_kem_wrapped_shared_secret.message).decapsulated_key,
            my_ephemeral_secret_key=my_ephemeral_secret_key)

    @ReplayErrorBackToUser
    def _handle_reject_connection(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        Handle a rejection from a Node Y to connect to this Node X. Node X will have already sent a CONN_REQ to NODE
        Y; thus it stands that Node Y will always come after Node X in the route.
        :param addr:
        :return:
        """

        # Remove the connection information for the rejecting node.
        conversation_id = (connection_token, addr)
        self._cleanup_connection(addr, connection_token)
        self._conversations.pop(conversation_id)

    @ReplayErrorBackToUser
    def _handle_extend_connection(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        This command in received from a node previous to this one in the route, to extend the connection to the next
        node in the route. The data will be the next node's address. This connection will send the next node a CONN_REQ
        command to extend the connection, and then forward the ephemeral public key back to the first node in the route
        for packet key exchanges later.
        :param addr:
        :return:
        """

        # Get the address and static public key of the next node in the route to extend the connection to. The static
        # public key could be obtained from the DHT from the "target_addr", but it can be sent to reduce DHT lookups.
        target_addr, their_static_public_key = pickle.loads(data)

        # Create an ephemeral public key, sign it, and send it to the next node in the route. This establishes e2e
        # encryption over the connection.
        my_static_private_key = KeyPair().import_("./_keys/me", "static").secret_key
        my_ephemeral_public_key, my_ephemeral_private_key = KEM.generate_key_pair()
        signed_ephemeral_public_key = DigitalSigning.sign(
            my_static_private_key=my_static_private_key,
            message=my_ephemeral_public_key,
            their_id=their_static_public_key)

        # Register the connection in the conversation list.
        conversation_id = (connection_token, addr)
        self._conversations[conversation_id] = ControlConnectionConversationInfo(
            state=ControlConnectionState.WAITING_FOR_ACK,
            their_static_public_key=their_static_public_key,
            shared_secret=None,
            my_ephemeral_secret_key=my_ephemeral_private_key)

        # Send the signed ephemeral public key to the next node, maintaining the connection token.
        sending_data = pickle.dumps(signed_ephemeral_public_key)
        self._send_message(target_addr, connection_token, ControlConnectionProtocol.CONN_REQ, sending_data)

    @ReplayErrorBackToUser
    def _forward_message(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        Forward a message to a node. The message could have come from a node either side of this one. Because every node
        connected to this one will have a corresponding node on the other side, linked by the connection token, the
        address of the target node will be the other node in the conversation list who has the same connection token as
        the node who is requesting the message be forwarded. Because the "recv_message" and "send_message" methods are
        used, e2e encryption and decryption will be handled automatically.
        :param addr:
        :param data:
        """

        # Get the address of the other node in the conversation list who has the same connection token.
        candidates = [c[1] for c in self._conversations.keys() if c[0] == connection_token and c[1] != addr]
        assert len(candidates) == 1
        target_node = candidates[0]

        # Get the next command and data from the message, and send it to the target node. The "next_data" may still be
        # ciphertext if the intended target isn't the next node (could be the node after that), with multiple nested
        # messages of "CONN_FWD" commands.
        next_command, next_data = self._parse_message(data)

        # Send the message to the target node. It will be automatically encrypted.
        self._send_message(target_node, connection_token, next_command, next_data)

    def _send_message(self, addr: Address, connection_token: Bytes, command: ControlConnectionProtocol, data: Bytes) -> None:
        """
        Send a message to a node, with a command and accompanying data. If a shared secret exists for the node, the data
        will be encrypted before being sent. This always happens after the initial key exchange with an authenticated
        KEM.
        :param addr:
        :param command:
        :param data:
        """

        # Add the command to the data.
        data = command.value.to_bytes(1, "big") + data

        # Encrypt the data if a shared secret exists (only won't when initiating a connection).
        conversation_id = (connection_token, addr)
        if self._conversations[conversation_id].shared_secret:
            symmetric_key = self._conversations[conversation_id].shared_secret
            data = SecureBytes(data)
            data = SymmetricEncryption.encrypt(data, symmetric_key).raw

        # Send the data to the node.
        self._udp_server.sendto(data, addr)

    def _waiting_for_ack_from(self, addr: Address, connection_token: Bytes) -> bool:
        conversation_id = (connection_token, addr)
        return addr in self._conversations and self._conversations[conversation_id] == ControlConnectionState.WAITING_FOR_ACK

    def _is_connected_to(self, addr: Address, connection_token: Bytes) -> bool:
        conversation_id = (connection_token, addr)
        return addr in self._conversations and self._conversations[conversation_id] == ControlConnectionState.CONNECTED
