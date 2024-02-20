from socket import socket as Socket, AF_INET, SOCK_DGRAM
from threading import Thread, Lock
from enum import Enum
from dataclasses import dataclass
import pickle

from src.crypto_engines.crypto.digital_signing import DigitalSigning, SignedMessage
from src.crypto_engines.crypto.key_encapsulation import KEM
from src.crypto_engines.crypto.symmetric_encryption import SymmetricEncryption
from src.crypto_engines.keys.key_pair import KeyPair
from src.crypto_engines.tools.secure_bytes import SecureBytes
from src.types import Bytes, Tuple, Str, Int, List, Dict, Optional


type Address = Tuple[Str, Int]


class ControlConnectionState(Enum):
    WAITING_FOR_CONNECTION_ACK = 0
    CONNECTED = 1


class ControlConnectionProtocol(Enum):
    CONN_REQ = 0b000
    CONN_ACC = 0b001
    CONN_REJ = 0b011
    CONN_CLS = 0b011
    CONN_ERR = 0b100


@dataclass
class ControlConnectionConversationInfo:
    state: ControlConnectionState
    their_static_public_key: SecureBytes
    shared_secret: SecureBytes
    my_ephemeral_secret_key: Optional[SecureBytes]


def ReplayErrorBackToUser(function):
    def outer(error_command):
        def inner(self, addr, data):
            try:
                function(self, addr, data)
            except Exception as e:
                self._send_message(addr, error_command, str(e))
        return inner
    return outer


class ControlConnectionManager:
    _udp_server: Socket
    _msg_threads: List[Thread]
    _conversations: Dict[Address, ControlConnectionConversationInfo]
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
            data, addr = self._udp_server.recvfrom(1024)
            msg_thread = Thread(target=self._handle_message, args=(data, addr))
            msg_thread.start()
            self._msg_threads.append(msg_thread)

    def _parse_message(self, data: Bytes) -> Tuple[ControlConnectionProtocol, Bytes]:
        # Parse the message into a command and data
        command = ControlConnectionProtocol(data[0])
        data = data[1:]
        return command, data

    def _handle_message(self, data: Bytes, addr: Address) -> None:
        command, data = self._parse_message(data)

        match command:
            case ControlConnectionProtocol.CONN_REQ:
                self._mutex.acquire()
                self._handle_request_to_connect(addr, data)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_ACC if self._waiting_for_ack_from(addr):
                self._mutex.acquire()
                self._handle_accept_connection(addr)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_REJ if self._waiting_for_ack_from(addr):
                self._mutex.acquire()
                self._handle_reject_connection(addr)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_CLS if self._is_connected_to(addr) or self._waiting_for_ack_from(addr):
                self._mutex.acquire()
                self._cleanup_connection(addr)
                self._mutex.release()

            case _:
                pass

    @ReplayErrorBackToUser(ControlConnectionProtocol.CONN_REJ)
    def _handle_request_to_connect(self, addr: Address, data: Bytes) -> None:
        """
        Handle a request from a Node to connect to this Node, and establish an encrypted tunnel for UDP traffic. The
        request will always come from a node that will be behind this node in the route.
        :param addr: Address of a node requesting this node to partake in a connection.
        :param data: Accompanying data with the request.
        """

        # Get their static public key from the DHT, and the parse the signed message.
        my_static_public_key, my_static_private_key = KeyPair().import_("./_keys/me", "static").both()
        their_static_public_key : SecureBytes = DHT.get_static_public_key(addr)
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
        sending_data = SecureBytes(pickle.dumps(signed_kem_wrapped_shared_secret))
        self._send_message(addr, ControlConnectionProtocol.CONN_ACC, sending_data)

        # Save the connection information for the requesting node.
        self._conversations[addr] = ControlConnectionConversationInfo(
            state=ControlConnectionState.CONNECTED,
            their_static_public_key=their_static_public_key,
            shared_secret=kem_wrapped_shared_secret.decapsulated_key,
            my_ephemeral_secret_key=None)

    @ReplayErrorBackToUser
    def _handle_accept_connection(self, addr: Address, data: Bytes) -> None:
        """
        Handle an acceptance from a Node Y to connect to this Node X. Node X will have already sent a CONN_REQ to NODE
        Y; thus it stands that Node Y will always come after Node X in the route.
        :param addr:
        :return:
        """

        # Get the signed KEM wrapped shared secret from the data, and verify the signature.
        my_static_public_key, my_static_private_key = KeyPair().import_("./_keys/me", "static").both()
        their_static_public_key = DHT.get_static_public_key(addr)
        signed_kem_wrapped_shared_secret: SignedMessage = pickle.loads(data)

        # Verify the signature of the KEM wrapped shared secret being sent from the accepting node.
        DigitalSigning.verify(
            their_static_public_key=their_static_public_key,
            signed_message=signed_kem_wrapped_shared_secret,
            my_id=my_static_public_key)

        # Save the connection information for the accepting node.
        my_ephemeral_secret_key = self._conversations[addr].my_ephemeral_secret_key
        self._conversations[addr] = ControlConnectionConversationInfo(
            state=ControlConnectionState.CONNECTED,
            their_static_public_key=their_static_public_key,
            shared_secret=KEM.kem_unwrap(my_ephemeral_secret_key, signed_kem_wrapped_shared_secret.message).decapsulated_key,
            my_ephemeral_secret_key=my_ephemeral_secret_key)

    @ReplayErrorBackToUser
    def _handle_reject_connection(self, addr: Address, data: Bytes) -> None:
        """
        Handle a rejection from a Node Y to connect to this Node X. Node X will have already sent a CONN_REQ to NODE
        Y; thus it stands that Node Y will always come after Node X in the route.
        :param addr:
        :return:
        """

        # Remove the connection information for the rejecting node.
        self._cleanup_connection(addr)
        self._conversations.pop(addr)

    def _send_message(self, addr: Address, command: ControlConnectionProtocol, data: SecureBytes) -> None:
        """
        Send a message to a node, with a command and accompanying data. If a shared secret exists for the node, the data
        will be encrypted before being sent. This always happens after the initial key exchange with an authenticated
        KEM.
        :param addr:
        :param command:
        :param data:
        """

        # Add the command to the data, and encrypt the data if a shared secret exists.
        data = SecureBytes(command.value.to_bytes(1, "big")) + data
        if self._conversations[addr].shared_secret:
            data = SymmetricEncryption.encrypt(data, self._conversations[addr].shared_secret)

        # Send the data to the node.
        self._udp_server.sendto(data.raw, addr)

    def _waiting_for_ack_from(self, addr: Address) -> bool:
        return addr in self._conversations and self._conversations[addr] == ControlConnectionState.WAITING_FOR_CONNECTION_ACK

    def _is_connected_to(self, addr: Address) -> bool:
        return addr in self._conversations and self._conversations[addr] == ControlConnectionState.CONNECTED
