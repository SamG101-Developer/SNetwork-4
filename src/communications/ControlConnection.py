import pickle, socket
from enum import Enum
from pickle import UnpicklingError
from threading import Thread, Lock
from abc import ABC, abstractmethod

from src.crypto_engines.crypto.digital_signing import DigitalSigning, SignedMessage
from src.crypto_engines.crypto.key_encapsulation import KEM
from src.crypto_engines.keys.key_pair import KeyPair


class ControlConnectionProtocol(Enum):
    CONN_REQ = 0
    CONN_ACC = 1
    CONN_REJ = 2
    CONN_CLS = 3


class ControlConnectionState(Enum):
    WAITING_FOR_CONNECTION_ACK = 0
    CONNECTED = 1


class ControlConnection(ABC):
    @abstractmethod
    def _handle_message(self, who: socket.socket, command: ControlConnectionProtocol, data: bytes) -> None:
        pass


class ControlConnectionB(ControlConnection):
    """
    The Backwards Control Connection is maintained between two nodes for sending control information and exchanging
    information regarding packet encryption keys. A node will receive a connection request, and then respond with an
    acceptance or rejection message.

    The node being communicated with will be before this node in the route. This means that this connection class is
    specifically to communicate with a prior node. Communicating with the next node in the route is done through the
    Forward Control Connection.
    """

    _socket: socket.socket
    _socket_threads: list[Thread]
    _conversations: dict[socket.socket, ControlConnectionState]
    _mutex: Lock

    def __init__(self):
        self._socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self._socket_threads = []
        self._conversations = {}
        self._mutex = Lock()
        self._setup_socket()

    def _handle_message(self, who: socket.socket, command: ControlConnectionProtocol, data: bytes) -> None:
        match command:
            case ControlConnectionProtocol.CONN_REQ:
                self._mutex.acquire()
                self._conversations[who] = ControlConnectionState.WAITING_FOR_CONNECTION_ACK
                self._handle_request_to_connect(who, data)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_ACC if who in self._conversations and self._conversations[who] == ControlConnectionState.WAITING_FOR_CONNECTION_ACK:
                self._mutex.acquire()
                self._conversations[who] = ControlConnectionState.CONNECTED
                self._mutex.release()

            case ControlConnectionProtocol.CONN_REJ if who in self._conversations and self._conversations[who] == ControlConnectionState.WAITING_FOR_CONNECTION_ACK:
                self._mutex.acquire()
                del self._conversations[who]
                self._mutex.release()

            case ControlConnectionProtocol.CONN_CLS if who in self._conversations:
                self._cleanup_connection(who)
                self._mutex.acquire()
                del self._conversations[who]
                self._mutex.release()

    def _handle_request_to_connect(self, who: socket.socket, data: bytes) -> None:
        # Get the public key of the node requesting a connection.
        their_static_public_key = DHT.get_static_public_key(who)

        # Load the message from data into a SignedMessage object, and ensure that the object is a SignedMessage object.
        try:
            signed_message = pickle.loads(data)
            assert isinstance(signed_message, SignedMessage)
        except (UnpicklingError, AssertionError):
            self._send_response(who, ControlConnectionProtocol.CONN_REJ, "Invalid message format")
            return

        # Verify the signature of the ephemeral public key being sent from the requesting node, first checking that the
        # object received is a SignedMessage object.
        try:
            DigitalSigning.verify(
                their_static_public_key=their_static_public_key,
                signed_message=signed_message,
                my_id=KeyPair().import_("./_keys/me", "static").public_key)

        except AssertionError as e:
            self._send_response(who, ControlConnectionProtocol.CONN_REJ, str(e))

        # Their ephemeral public key was the data signed in the message. Use it to encapsulate a key pair, and sign the
        # encapsulated key pair. This node creates the KEM and sends it, so that ephemeral keys can be used, ensuring
        # perfect forward secrecy over control connections.
        their_ephemeral_public_key = signed_message.message
        kem_key_pair = KEM.kem_wrap(their_ephemeral_public_key)
        signed_kem_key_pair = DigitalSigning.sign(
            my_static_private_key=KeyPair().import_("./_keys/me", "static").secret_key,
            message=kem_key_pair.encapsulated_key,
            their_id=their_static_public_key)

        # Send the connection acceptance message, containing the signed encapsulated key pair.
        self._send_response(who, ControlConnectionProtocol.CONN_ACC, signed_kem_key_pair)

    def _send_response(self, who: socket.socket, command: ControlConnectionProtocol, data: object) -> None:
        self._socket.sendto(pickle.dumps((command, data)), who.getpeername())

    def _handle_connection(self, connection: socket.socket, address: tuple[str, int]) -> None:
        while True:
            data, _ = connection.recvfrom(1024)
            command, data = pickle.loads(data)
            self._handle_message(connection, command, data)

    def _setup_socket(self) -> None:
        # Bind to port 12345 for public connections, allow up to 5 connections to be queued.
        self._socket.bind(("", 12345))
        self._socket.listen(5)

        # Create a thread for each incoming connection.
        while True:
            connection, address = self._socket.accept()
            thread = Thread(target=self._handle_connection, args=(connection, address))
            self._socket_threads.append(thread)
            thread.start()
