from __future__ import annotations

import time
from threading import Thread, Lock
from enum import Enum
from dataclasses import dataclass
from argparse import Namespace
import logging, os, pickle, socket

from control_communications.ControlConnectionServer import ControlConnectionServer
from crypto_engines.crypto.digital_signing import DigitalSigning, SignedMessage
from crypto_engines.crypto.key_encapsulation import KEM
from crypto_engines.crypto.symmetric_encryption import SymmetricEncryption
from crypto_engines.keys.key_pair import KeyPair, KEMKeyPair
from crypto_engines.tools.secure_bytes import SecureBytes
from distributed_hash_table.DHT import DHT
from my_types import Bytes, Tuple, Str, Int, List, Dict, Optional


@dataclass(kw_only=True)
class Address:
    ip: Str
    port: Int

    def socket_format(self) -> Tuple[Str, Int]:
        return self.ip, self.port

    @staticmethod
    def me() -> Address:
        return Address(ip=socket.gethostbyname(socket.gethostname()), port=12345)

    def __hash__(self):
        from hashlib import md5
        return int(md5(self.ip.encode()).hexdigest(), 16) % 2**64


@dataclass(kw_only=True)
class ConnectionToken:
    token: Bytes
    address: Address

    def __hash__(self):
        return (hash(self.token) * hash(self.address)) % 2**64


class ControlConnectionState(Enum):
    WAITING_FOR_ACK = 0
    CONNECTED = 1


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


@dataclass(kw_only=True)
class ControlConnectionConversationInfo:
    state: ControlConnectionState
    their_static_public_key: SecureBytes
    shared_secret: Optional[SecureBytes]
    my_ephemeral_public_key: Optional[SecureBytes]
    my_ephemeral_secret_key: Optional[SecureBytes]


def ReplayErrorBackToUser(error_command):
    def outer(function):
        def inner(self, addr, conversation_token, data):
            try:
                function(self, addr, data)
            except Exception as e:
                self._send_message(addr, conversation_token, error_command, str(e))
        return inner
    return outer


def LogPre(function):
    def inner(self, *args):
        logging.info(f"ConnectionControlManager::{function.__name__}")
        return function(self, *args)
    return inner


@dataclass(kw_only=True)
class ControlConnectionRouteNode:
    connection_token: ConnectionToken
    ephemeral_key_pair: Optional[KeyPair]
    shared_secret: Optional[KEMKeyPair]


@dataclass(kw_only=True)
class ControlConnectionRoute:
    route: List[ControlConnectionRouteNode]
    connection_token: ConnectionToken


class ControlConnectionManager:
    _udp_server: ControlConnectionServer
    _conversations: Dict[ConnectionToken, ControlConnectionConversationInfo]
    _my_route: Optional[ControlConnectionRoute]
    _node_to_client_tunnel_keys: Dict[Bytes, ControlConnectionRouteNode]
    _pending_node_to_add_to_route: Optional[Address]
    _mutex: Lock
    _server_socket_thread: Thread

    def __init__(self):
        # Setup the attributes of the control connection manager
        self._udp_server = ControlConnectionServer()
        self._udp_server.on_message_received = self._recv_message

        self._conversations = {}
        self._my_route = None
        self._node_to_client_tunnel_keys = {}
        self._mutex = Lock()

    @LogPre
    def create_route(self, _arguments: Namespace) -> None:
        if self._my_route:
            return

        # To create the route, the client will tell itself to extend the connection to the first node in the route. Each
        # time a new node is added, the communication flows via every node in the existing network, so only the first
        # node in the route knows the client node.
        connection_token = ConnectionToken(token=os.urandom(32), address=Address.me())
        route_node = ControlConnectionRouteNode(connection_token=connection_token, ephemeral_key_pair=None, shared_secret=None)
        self._my_route = ControlConnectionRoute(route=[route_node], connection_token=connection_token)

        # Add the conversation to myself
        self._conversations[connection_token] = ControlConnectionConversationInfo(
            state=ControlConnectionState.CONNECTED,
            their_static_public_key=KeyPair().import_("./_keys/me", "static").public_key,
            shared_secret=None,
            my_ephemeral_public_key=None,
            my_ephemeral_secret_key=None)

        # Extend the connection (use a while loop so failed connections don't affect the node counter for route length).
        while len(self._my_route.route) < 4:

            # Extend the connection to the next node in the route.
            current_ips_in_route = [node.connection_token.address.ip for node in self._my_route.route]
            self._pending_node_to_add_to_route = Address(ip=DHT.get_random_node(current_ips_in_route), port=12345)
            self._send_layered_message_forward(connection_token.token, ControlConnectionProtocol.CONN_EXT, b"")

            # Wait for the next node to be added to the route.
            while self._pending_node_to_add_to_route:
                pass

        # Log the route.
        logging.info(f"\t\tCreated route: {' -> '.join([node.connection_token.address.ip for node in self._my_route.route])}")

    @LogPre
    def _layer_encrypt(self, data: Bytes) -> Bytes:
        for node in reversed(self._my_route.route[1:]):  # todo : encrypt to self
            data = ControlConnectionProtocol.CONN_FWD.value.to_bytes(1, "big") + node.connection_token.address.ip.encode() + data
            data = SymmetricEncryption.encrypt(SecureBytes(data), node.shared_secret.decapsulated_key).raw

        logging.debug(f"\t\tLayer encrypted data: {data[:10]}...")
        return data

    @LogPre
    def _layer_decrypt(self, data: Bytes) -> Bytes:
        for node in self._my_route.route[1:]:
            assert ControlConnectionProtocol(data[0]) == ControlConnectionProtocol.CONN_FWD
            data = SymmetricEncryption.decrypt(SecureBytes(data), node.shared_secret.decapsulated_key).raw
            data = data[1:]
        return data[1:]

    @LogPre
    def _recv_message(self, data: Bytes, raw_addr: Tuple[Str, Int]) -> None:
        # Get the data and address from the udp socket, and parse the message into a command and data. Split the data
        # into the connection token and the rest of the data.
        addr = Address(ip=raw_addr[0], port=raw_addr[1])
        known_addresses = [c.address.ip for c in self._conversations.keys()]

        logging.debug(f"\t\tRaw data: {data[:20]}...")

        # Decrypt forwarded messages from the route, if the message is forwarded.
        if data[0] == ControlConnectionProtocol.CONN_FWD.value:
            data = self._layer_decrypt(data)

        # Decrypt the data in a conversation, which won't have been initiated if this is the request to connect.
        elif raw_addr[0] in known_addresses:
            conversation_id = list(self._conversations.keys())[known_addresses.index(raw_addr[0])]
            if self._conversations[conversation_id].shared_secret:
                symmetric_key = self._conversations[conversation_id].shared_secret
                data = SecureBytes(data)
                data = SymmetricEncryption.decrypt(data, symmetric_key).raw
                logging.debug(f"\t\tDecrypted data: {data[:20]}...")

        # Parse the data into the components of the message.
        command, connection_token, data = self._parse_message(data)

        # Log the message & associated data.
        logging.debug(f"\t\tMessage from: {addr.ip}")
        logging.debug(f"\t\tCommand: {command}")
        logging.debug(f"\t\tData: {data[:10]}...")

        # Create a new thread to handle the message, and add it to the list of message threads.
        self._handle_message(addr, command, connection_token, data)

    @LogPre
    def _parse_message(self, data: Bytes) -> Tuple[ControlConnectionProtocol, Bytes, Bytes]:
        """
        Parse the message into a command, connection token and data. The command is the first byte, the connection token
        is the next 32 bytes, and the rest of the data is the accompanying data.
        :param data:
        :return:
        """

        # Split the data into the command, connection token and the rest of the data.
        command = ControlConnectionProtocol(data[0])
        connection_token = data[1:33]
        data = data[33:]

        # Return the command, connection token and data.
        return command, connection_token, data

    @LogPre
    def _handle_message(self, addr: Address, command: ControlConnectionProtocol, connection_token: Bytes, data: Bytes) -> None:
        """
        Handle a message from a node. The message will have already been split into the command, connection token and
        the accompanying data. The message will be handled based on the command. After the function for the command has
        executed, the current thread is joined and removed from the list of message threads.
        :param addr:
        :param command:
        :param connection_token:
        :param data:
        :return:
        """

        waiting_for_ack = self._waiting_for_ack_from(addr, connection_token)
        connected = self._is_connected_to(addr, connection_token)
        in_route = self._is_in_route(addr, connection_token)

        # Decide on the function to call based on the command, and call it. The mutex is used to lock the conversation
        # list, so that only one thread can access it at a time. This is to prevent
        match command:
            case ControlConnectionProtocol.CONN_REQ:
                self._mutex.acquire()
                self._handle_request_to_connect(addr, connection_token, data)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_ACC if waiting_for_ack:
                self._mutex.acquire()
                self._handle_accept_connection(addr, connection_token, data)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_PKT_KEM if connected or waiting_for_ack:
                self._mutex.acquire()
                self._handle_accept_connection_attach_key_to_client(addr, connection_token, data)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_REJ if waiting_for_ack:
                self._mutex.acquire()
                self._handle_reject_connection(addr, connection_token, data)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_CLS if waiting_for_ack or connected:
                self._mutex.acquire()
                self._cleanup_connection(addr, connection_token)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_EXT if connected:
                self._mutex.acquire()
                self._handle_extend_connection(addr, connection_token, data)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_EXT_ACC if connected:
                self._mutex.acquire()
                self._handle_accept_extended_connection(addr, connection_token, data)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_EXT_REJ if connected:
                self._mutex.acquire()
                self._handle_reject_extended_connection(addr, connection_token, data)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_FWD:
                self._mutex.acquire()
                self._forward_message(addr, data)
                self._mutex.release()

            case ControlConnectionProtocol.CONN_PKT_KEY if in_route:
                self._mutex.acquire()
                self._handle_packet_key(addr, connection_token, data)
                self._mutex.release()

            case _:
                pass

        # End this handler thread, and remove it from the list of message threads.
        # current_thread = threading.current_thread()
        # self._msg_threads.remove(current_thread)
        # current_thread.join()  # TODO

    @LogPre
    # @ReplayErrorBackToUser(ControlConnectionProtocol.CONN_REJ)
    def _handle_request_to_connect(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        Handle a request from a Node to connect to this Node, and establish an encrypted tunnel for UDP traffic. The
        request will always come from a node that will be behind this node in the route.
        :param addr: Address of a node requesting this node to partake in a connection.
        :param data: Accompanying data with the request.
        """

        # Get their static public key from the DHT, and the parse the signed message.
        my_static_private_key, my_static_public_key = KeyPair().import_("./_keys/me", "static").both()
        their_static_public_key = DHT.get_static_public_key(addr.ip)
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

        logging.debug(f"\t\tTheir ephemeral public key: {their_ephemeral_public_key.raw[:10]}...")
        logging.debug(f"\t\tShared secret: {kem_wrapped_shared_secret.encapsulated_key.raw[:10]}...")
        logging.debug(f"\t\tKEM wrapped shared secret: {kem_wrapped_shared_secret.encapsulated_key.raw[:10]}...")
        logging.debug(f"\t\tSigned KEM wrapped shared secret: {signed_kem_wrapped_shared_secret.signature.raw[:10]}...")

        # Create a key for the new node, to allow e2e encrypted tunnel via the other nodes in the circuit.
        conversation_id = ConnectionToken(token=connection_token, address=addr)
        self._node_to_client_tunnel_keys[connection_token] = ControlConnectionRouteNode(
            connection_token=conversation_id,
            ephemeral_key_pair=KEM.generate_key_pair(),
            shared_secret=None)

        signed_e2e_key = DigitalSigning.sign(
            message=self._node_to_client_tunnel_keys[connection_token].ephemeral_key_pair.public_key,
            my_static_private_key=my_static_private_key,
            their_id=their_static_public_key)

        # Send the signed KEM wrapped shared secret to the requesting node.
        self._send_message(addr, connection_token, ControlConnectionProtocol.CONN_ACC, pickle.dumps(signed_kem_wrapped_shared_secret))
        self._send_message(addr, connection_token, ControlConnectionProtocol.CONN_PKT_KEM, pickle.dumps(signed_e2e_key))

        # Save the connection information for the requesting node.
        self._conversations[conversation_id] = ControlConnectionConversationInfo(
            state=ControlConnectionState.CONNECTED,
            their_static_public_key=their_static_public_key,
            shared_secret=kem_wrapped_shared_secret.decapsulated_key,
            my_ephemeral_public_key=None,
            my_ephemeral_secret_key=None)

    @LogPre
    # @ReplayErrorBackToUser
    def _handle_accept_connection(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        Handle an acceptance from a Node Y to connect to this Node X. Node X will have already sent a CONN_REQ to NODE
        Y; thus it stands that Node Y will always come after Node X in the route.
        :param addr:
        :return:
        """

        # Get the signed KEM wrapped shared secret from the data, and verify the signature.
        my_static_private_key, my_static_public_key = KeyPair().import_("./_keys/me", "static").both()
        their_static_public_key = DHT.get_static_public_key(addr.ip)
        signed_kem_wrapped_shared_secret = pickle.loads(data)

        # Verify the signature of the KEM wrapped shared secret being sent from the accepting node.
        DigitalSigning.verify(
            their_static_public_key=their_static_public_key,
            signed_message=signed_kem_wrapped_shared_secret,
            my_id=my_static_public_key)

        # Save the connection information for the accepting node.
        conversation_id = ConnectionToken(token=connection_token, address=addr)
        my_ephemeral_public_key = self._conversations[conversation_id].my_ephemeral_public_key
        my_ephemeral_secret_key = self._conversations[conversation_id].my_ephemeral_secret_key

        self._conversations[conversation_id] = ControlConnectionConversationInfo(
            state=ControlConnectionState.CONNECTED,
            their_static_public_key=their_static_public_key,
            shared_secret=KEM.kem_unwrap(my_ephemeral_secret_key, signed_kem_wrapped_shared_secret.message).decapsulated_key,
            my_ephemeral_public_key=my_ephemeral_public_key,
            my_ephemeral_secret_key=my_ephemeral_secret_key)

        logging.debug(f"\t\tShared secret: {self._conversations[conversation_id].shared_secret.raw[:10]}...")

    @LogPre
    def _handle_accept_connection_attach_key_to_client(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        my_static_private_key, my_static_public_key = KeyPair().import_("./_keys/me", "static").both()
        their_static_public_key = DHT.get_static_public_key(addr.ip)
        signed_e2e_pub_key = pickle.loads(data)

        logging.debug(f"\t\tTheir signed e2e public key: {signed_e2e_pub_key.signature.raw[:10]}...")
        logging.debug(f"\t\tTheir e2e public key: {signed_e2e_pub_key.message.raw[:10]}...")

        DigitalSigning.verify(
            their_static_public_key=their_static_public_key,
            signed_message=signed_e2e_pub_key,
            my_id=my_static_public_key)

        candidates = [c.address for c in self._conversations.keys() if c.token == connection_token and c.address != addr]
        assert len(candidates) == 1
        target_node = candidates[0]

        logging.debug(f"\t\tSending e2e public key to: {target_node.ip}")

        self._send_layered_message_backward(target_node, connection_token, ControlConnectionProtocol.CONN_EXT_ACC, pickle.dumps(signed_e2e_pub_key))

    @LogPre
    # @ReplayErrorBackToUser
    def _handle_reject_connection(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        Handle a rejection from a Node Y to connect to this Node X. Node X will have already sent a CONN_REQ to NODE
        Y; thus it stands that Node Y will always come after Node X in the route.
        :param addr:
        :return:
        """

        # Tell the previous node that the extension was rejected (if this node isn't the client node)
        candidates = [c.address for c in self._conversations.keys() if c.token == connection_token and c.address != addr]
        assert len(candidates) in (0, 1)
        if candidates:
            target_node = candidates[0]
            self._send_message(target_node, connection_token, ControlConnectionProtocol.CONN_EXT_REJ, data)

        # Remove the connection information for the rejecting node.
        conversation_id = ConnectionToken(token=connection_token, address=addr)
        self._cleanup_connection(addr, connection_token)
        self._conversations.pop(conversation_id)

    @LogPre
    # @ReplayErrorBackToUser
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
        target_addr = self._pending_node_to_add_to_route
        target_static_public_key = DHT.get_static_public_key(target_addr.ip)
        logging.debug(f"\t\tExtending to: {target_addr.ip}")

        # Create an ephemeral public key, sign it, and send it to the next node in the route. This establishes e2e
        # encryption over the connection.
        my_static_private_key = KeyPair().import_("./_keys/me", "static").secret_key
        my_ephemeral_private_key, my_ephemeral_public_key = KEM.generate_key_pair().both()

        logging.debug(f"\t\tGenerated ephemeral public key: {my_ephemeral_public_key.raw[:10]}...")
        logging.debug(f"\t\tGenerated ephemeral secret key: {my_ephemeral_private_key.raw[:10]}...")

        # Register the connection in the conversation list.
        conversation_id = ConnectionToken(token=connection_token, address=target_addr)
        self._conversations[conversation_id] = ControlConnectionConversationInfo(
            state=ControlConnectionState.WAITING_FOR_ACK,
            their_static_public_key=target_static_public_key,
            shared_secret=None,
            my_ephemeral_public_key=my_ephemeral_public_key,
            my_ephemeral_secret_key=my_ephemeral_private_key)

        # Send the signed ephemeral public key to the next node, maintaining the connection token. The next node will
        # ultimately send an EXT_ACK command to acknowledge the extension.
        signed_my_ephemeral_public_key = DigitalSigning.sign(
            my_static_private_key=my_static_private_key,
            message=my_ephemeral_public_key,
            their_id=target_static_public_key)

        logging.debug(f"\t\tSigned ephemeral public key: {signed_my_ephemeral_public_key.signature.raw[:10]}...")

        sending_data = pickle.dumps(signed_my_ephemeral_public_key)
        self._send_message(target_addr, connection_token, ControlConnectionProtocol.CONN_REQ, sending_data)

    @LogPre
    # @ReplayErrorBackToUser
    def _handle_accept_extended_connection(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        A connection extension has been accepted. This means Node X has told Node Y to extend the connection to Node Z,
        and Node Z has accepted Node Y's connection, so Node Y is telling this to Node X.
        :param addr:
        :param connection_token:
        :param data:
        :return:
        """

        logging.debug(f"\t\tAccepting extension to: {addr.ip}")
        logging.debug(f"\t\tConnection token: {connection_token}")
        logging.debug(f"\t\tData: {data[:10]}...")

        # If this is the client node accepting the extension to the route, add the node to the route list.
        if self._my_route and self._my_route.connection_token.token == connection_token:
            # Get the signed ephemeral public key from the data, and verify the signature. The key from Node Z was
            # originally sent to Node Y, so the identifier of Node Y is used to verify the signature.
            current_final_node_static_public_key = DHT.get_static_public_key(self._my_route.route[-1].connection_token.address.ip)
            their_static_public_key = DHT.get_static_public_key(self._pending_node_to_add_to_route.ip)
            signed_ephemeral_public_key: SignedMessage = pickle.loads(data)

            # Log the signed ephemeral public key.
            logging.debug(f"\t\tTheir ephemeral public key: {signed_ephemeral_public_key.message.raw[:10]}...")
            logging.debug(f"\t\tTheir signed ephemeral public key: {signed_ephemeral_public_key.signature.raw[:10]}...")

            # Verify the signature of the ephemeral public key being sent from the accepting node.
            DigitalSigning.verify(
                their_static_public_key=their_static_public_key,
                signed_message=signed_ephemeral_public_key,
                my_id=current_final_node_static_public_key)

            # Check that the command (signed by the target node being extended to), is indeed what the next node
            # reported. This is to prevent the next node lying about the state of the connection. If the next node is
            # lying, this node needs changing. TODO: Remove lying node
            target_cmd, target_connection_token, data = self._parse_message(signed_ephemeral_public_key.message.raw)
            assert target_cmd == ControlConnectionProtocol.CONN_EXT_ACC
            assert target_connection_token == connection_token

            # Verify the signature of the ephemeral public key being sent from the accepting node.
            DigitalSigning.verify(
                their_static_public_key=their_static_public_key,
                signed_message=signed_ephemeral_public_key,
                my_id=current_final_node_static_public_key)

            # Save the connection information to the route list.
            self._my_route.route.append(ControlConnectionRouteNode(
                connection_token=ConnectionToken(token=connection_token, address=self._pending_node_to_add_to_route),
                ephemeral_key_pair=KeyPair(public_key=signed_ephemeral_public_key.message),
                shared_secret=KEM.kem_wrap(signed_ephemeral_public_key.message)))

            # Note: vulnerable to MITM, so use unilateral authentication later. TODO
            self._pending_node_to_add_to_route = None
            self._send_layered_message_forward(connection_token, ControlConnectionProtocol.CONN_PKT_KEY, self._my_route.route[-1].shared_secret.encapsulated_key.raw)

        # Otherwise, send this message to the previous node in the route.
        else:
            candidates = [c.address for c in self._conversations.keys() if c.token == connection_token and c.address != addr]
            assert len(candidates) == 1
            target_node = candidates[0]
            self._send_message(target_node, connection_token, ControlConnectionProtocol.CONN_EXT_ACC, data)

    @LogPre
    # @ReplayErrorBackToUser
    def _handle_reject_extended_connection(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        A connection extension has been rejected. This means Node X has told Node Y to extend the connection to Node Z,
        and Node Z has rejected Node Y's connection, so Node Y is telling this to Node X.
        :param addr:
        :param connection_token:
        :param data:
        :return:
        """

        # If this is the client node accepting the extension to the route, then a new node needs to be requested to be
        # added to the route list.
        if self._my_route and self._my_route.connection_token.token == connection_token:
            their_static_public_key = DHT.get_static_public_key(self._pending_node_to_add_to_route.ip)
            original_node_static_public_key = DHT.get_static_public_key(self._my_route.route[-1].connection_token.address.ip)
            rejection_message: SignedMessage = pickle.loads(data)

            # Verify the signature of the rejection message being sent from the rejecting node.
            DigitalSigning.verify(
                their_static_public_key=their_static_public_key,
                signed_message=rejection_message,
                my_id=original_node_static_public_key)

            # Check that the command (signed by the target node being extended to), is indeed what the next node
            # reported. This is to prevent the next node lying about the state of the connection. If the next node is
            # lying, this node needs changing. TODO: Remove lying node
            target_cmd, target_connection_token, rejection_data = self._parse_message(rejection_message.message.raw)
            assert target_cmd == ControlConnectionProtocol.CONN_EXT_REJ
            assert target_connection_token == connection_token

            # TODO: Request a new node to be added to the route list
            self._pending_node_to_add_to_route = None

        # Otherwise, send this message to the previous node in the route.
        else:
            candidates = [c.address for c in self._conversations.keys() if c.token == connection_token and c.address != addr]
            assert len(candidates) == 1
            target_node = candidates[0]
            self._send_message(target_node, connection_token, ControlConnectionProtocol.CONN_EXT_REJ, data)

    @LogPre
    def _handle_packet_key(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        conversation_id = ConnectionToken(token=connection_token, address=addr)
        my_ephemeral_secret_key = self._node_to_client_tunnel_keys[connection_token].ephemeral_key_pair.secret_key
        self._node_to_client_tunnel_keys[connection_token].shared_secret = KEM.kem_unwrap(my_ephemeral_secret_key, SecureBytes(data))

    @LogPre
    # @ReplayErrorBackToUser
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
        candidates = [c.address for c in self._conversations.keys() if c.token == connection_token and c.address != addr]
        assert len(candidates) == 1
        target_node = candidates[0]

        # Get the next command and data from the message, and send it to the target node. The "next_data" may still be
        # ciphertext if the intended target isn't the next node (could be the node after that), with multiple nested
        # messages of "CONN_FWD" commands.
        next_command, next_connection_token, next_data = self._parse_message(data)
        assert next_connection_token == connection_token

        # Send the message to the target node. It will be automatically encrypted.
        self._send_message(target_node, connection_token, next_command, next_data)

    @LogPre
    def _send_message(self, addr: Address, connection_token: Bytes, command: ControlConnectionProtocol, data: Bytes) -> None:
        """
        Send a message to a direct-neighbour node, with a command and accompanying data. If a shared secret exists for
        the node, the data will be encrypted before being sent. This always happens after the initial key exchange with
        an authenticated KEM. This DOES NOT use layered encryption to nodes. Use the self._send_layered_message method
        for that.
        :param addr:
        :param command:
        :param data:
        """

        logging.debug(f"\t\tSending message to: {addr.ip}")
        logging.debug(f"\t\tCommand: {command}")
        logging.debug(f"\t\tData: {data[:10]}...")

        # Add the command to the data.
        data = command.value.to_bytes(1, "big") + connection_token + data

        # Encrypt the data if a shared secret exists (only won't when initiating a connection).
        conversation_id = ConnectionToken(token=connection_token, address=addr)
        if self._is_connected_to(addr, connection_token) and self._conversations[conversation_id].shared_secret:
            symmetric_key = self._conversations[conversation_id].shared_secret
            data = SecureBytes(data)
            data = SymmetricEncryption.encrypt(data, symmetric_key).raw

            logging.debug(f"\t\tEncrypted data: {data[:10]}...")

        # Send the data to the node.
        self._udp_server.udp_send(data, addr.socket_format())

    @LogPre
    def _send_layered_message_forward(self, connection_token: Bytes, command: ControlConnectionProtocol, data: Bytes) -> None:
        assert isinstance(data, Bytes)

        logging.debug(f"\t\tSending layered message forwards")
        logging.debug(f"\t\tCommand: {command}")
        logging.debug(f"\t\tData: {data[:10]}...")

        data = self._layer_encrypt(data)
        data = command.value.to_bytes(1, "big") + connection_token + data
        self._udp_server.udp_send(data, self._my_route.route[0].connection_token.address.socket_format())

    @LogPre
    def _send_layered_message_backward(self, addr: Address, connection_token: Bytes, command: ControlConnectionProtocol, data: Bytes) -> None:
        assert isinstance(data, Bytes)

        logging.debug(f"\t\tSending layered message backwards")
        logging.debug(f"\t\tCommand: {command}")
        logging.debug(f"\t\tData: {data[:10]}...")

        data = command.value.to_bytes(1, "big") + connection_token + data
        if addr != Address.me():
            data = SymmetricEncryption.encrypt(SecureBytes(data), self._node_to_client_tunnel_keys[connection_token].shared_secret.decapsulated_key).raw
            data = ControlConnectionProtocol.CONN_FWD.value.to_bytes(1, "big") + connection_token + data
        self._udp_server.udp_send(data, addr.socket_format())

    @LogPre
    def _cleanup_connection(self, addr: Address, connection_token: Bytes) -> None:
        """
        Cleanup a connection, and remove the connection information from the conversation list. This will be called when
        a connection is closed, or when a connection is rejected.
        :param addr:
        :param connection_token:
        :return:
        """

        # Remove the connection information from the conversation list.
        conversation_id = ConnectionToken(token=connection_token, address=addr)
        self._conversations.pop(conversation_id)

    def _waiting_for_ack_from(self, addr: Address, connection_token: Bytes) -> bool:
        conversation_id = ConnectionToken(token=connection_token, address=addr)
        return conversation_id in self._conversations.keys() and self._conversations[conversation_id].state == ControlConnectionState.WAITING_FOR_ACK

    def _is_connected_to(self, addr: Address, connection_token: Bytes) -> bool:
        conversation_id = ConnectionToken(token=connection_token, address=addr)
        return conversation_id in self._conversations.keys() and self._conversations[conversation_id].state == ControlConnectionState.CONNECTED

    def _is_in_route(self, addr: Address, connection_token: Bytes) -> bool:
        conversation_id = ConnectionToken(token=connection_token, address=addr)
        return self._my_route and conversation_id in [n.connection_token for n in self._my_route.route]
