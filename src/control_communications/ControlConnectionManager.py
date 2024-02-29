from __future__ import annotations

import hashlib
from threading import Thread, Lock
from argparse import Namespace
import logging, os, pickle

from control_communications.ControlConnectionServer import ControlConnectionServer
from control_communications.ControlConnectionProtocol import ControlConnectionProtocol
from control_communications.ControlConnectionRoute import ControlConnectionRoute, ControlConnectionRouteNode, Address, ConnectionToken
from control_communications.ControlConnectionConversation import ControlConnectionConversationInfo, ControlConnectionState

from crypto_engines.crypto.digital_signing import DigitalSigning, SignedMessage
from crypto_engines.crypto.key_encapsulation import KEM
from crypto_engines.crypto.symmetric_encryption import SymmetricEncryption
from crypto_engines.keys.key_pair import KeyPair
from crypto_engines.tools.secure_bytes import SecureBytes
from distributed_hash_table.DHT import DHT
from my_types import Bytes, Tuple, Str, Int, Dict, Optional


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


class ControlConnectionManager:
    _udp_server: ControlConnectionServer
    _conversations: Dict[ConnectionToken, ControlConnectionConversationInfo]
    _my_route: Optional[ControlConnectionRoute]
    _node_to_client_tunnel_keys: Dict[Bytes, ControlConnectionRouteNode]
    _pending_node_to_add_to_route: Optional[Address]
    _mutex: Lock

    def __init__(self):
        # Setup the attributes of the control connection manager
        self._udp_server = ControlConnectionServer()
        self._udp_server.on_message_received = self._recv_message

        self._conversations = {}
        self._my_route = None
        self._node_to_client_tunnel_keys = {}
        self._pending_node_to_add_to_route = None

        self._mutex = Lock()

    @LogPre
    def create_route(self, _arguments: Namespace) -> None:
        if self._my_route:
            return

        # To create the route, the client will tell itself to extend the connection to the first node in the route. Each
        # time a new node is added, the communication flows via every node in the existing network, so only the first
        # node in the route knows the client node.
        FIXED_TOKEN = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")  # temp
        connection_token = ConnectionToken(token=FIXED_TOKEN, address=Address.me())
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
        while len(self._my_route.route) < 3:
            # Extend the connection to the next node in the route.
            current_ips_in_route = [node.connection_token.address.ip for node in self._my_route.route]
            self._pending_node_to_add_to_route = Address(ip=DHT.get_random_node(current_ips_in_route), port=12345)
            logging.info(f"\t\t\033[32mExtending route to: {self._pending_node_to_add_to_route.ip}\033[0m")

            self._tunnel_message_forwards(self._pending_node_to_add_to_route, connection_token.token, ControlConnectionProtocol.CONN_EXT, pickle.dumps(self._pending_node_to_add_to_route))

            # Wait for the next node to be added to the route.
            conversation_id = ConnectionToken(token=connection_token.token, address=self._pending_node_to_add_to_route)

            while conversation_id not in self._conversations:
                pass

            while True:
                if not (self._conversations[conversation_id].state & ControlConnectionState.SECURE): continue
                if not (self._conversations[conversation_id].state & ControlConnectionState.CONNECTED): continue
                break

        # Log the route.
        logging.info(f"\t\tCreated route: {' -> '.join([node.connection_token.address.ip for node in self._my_route.route])}")

    # @LogPre
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

        # logging.debug(f"\t\tParsed command: {command}")
        # logging.debug(f"\t\tParsed connection token: {connection_token}...")
        # logging.debug(f"\t\tParsed data: {data[:100]}...")

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
        # list, so that only one thread can access it at a time.
        # self._mutex.acquire()
        match command:
            case ControlConnectionProtocol.CONN_REQ:
                self._handle_request_to_connect(addr, connection_token, data)
                
            case ControlConnectionProtocol.CONN_ACC if waiting_for_ack:
                self._handle_accept_connection(addr, connection_token, data)
                
            case ControlConnectionProtocol.CONN_PKT_KEM if connected or waiting_for_ack:
                self._handle_accept_connection_attach_key_to_client(addr, connection_token, data)
                
            case ControlConnectionProtocol.CONN_REJ if waiting_for_ack:
                self._handle_reject_connection(addr, connection_token, data)
                
            case ControlConnectionProtocol.CONN_CLS if waiting_for_ack or connected:
                self._cleanup_connection(addr, connection_token)
                
            case ControlConnectionProtocol.CONN_EXT if connected:
                self._handle_extend_connection(addr, connection_token, data)
                
            case ControlConnectionProtocol.CONN_EXT_ACC if connected:
                self._handle_accept_extended_connection(addr, connection_token, data)
                
            case ControlConnectionProtocol.CONN_EXT_REJ if connected:
                self._handle_reject_extended_connection(addr, connection_token, data)
                
            case ControlConnectionProtocol.CONN_FWD:
                self._forward_message(addr, connection_token, data)
                
            case ControlConnectionProtocol.CONN_PKT_KEY:
                self._handle_packet_key(addr, connection_token, data)

            case ControlConnectionProtocol.CONN_PKT_ACK if connected:
                self._handle_packet_key_ack(addr, connection_token, data)
                
            case _:
                logging.error(f"\t\tUnknown command or invalid state: {command}")
                logging.error(f"\t\t{addr.ip} {self._pending_node_to_add_to_route.ip}")
                logging.error(f"\t\tWaiting for ack?: {waiting_for_ack}")
                logging.error(f"\t\tConnected?: {connected}")

        # self._mutex.release()

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

        logging.debug(f"\t\tTheir ephemeral public key: {their_ephemeral_public_key.raw[:100]}...")
        logging.debug(f"\t\tShared secret (CON): {kem_wrapped_shared_secret.decapsulated_key.raw[:100]}...")
        logging.debug(f"\t\tKEM-wrapped shared secret: {kem_wrapped_shared_secret.encapsulated_key.raw[:100]}...")
        logging.debug(f"\t\tSigned KEM wrapped shared secret: {signed_kem_wrapped_shared_secret.signature.raw[:100]}...")

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

        logging.debug(f"\t\tE2E public key: {hashlib.md5(signed_e2e_key.message.raw).hexdigest()}...")
        logging.debug(f"\t\tSigned E2E public key: {hashlib.md5(signed_e2e_key.signature.raw).hexdigest()}...")

        # Save the connection information for the requesting node.
        self._conversations[conversation_id] = ControlConnectionConversationInfo(
            state=ControlConnectionState.CONNECTED,
            their_static_public_key=their_static_public_key,
            shared_secret=None,
            my_ephemeral_public_key=None,
            my_ephemeral_secret_key=None)

        # Send the signed KEM wrapped shared secret to the requesting node.
        self._send_message_onwards(addr, connection_token, ControlConnectionProtocol.CONN_ACC, pickle.dumps(signed_kem_wrapped_shared_secret))
        self._tunnel_message_backward(addr, connection_token, ControlConnectionProtocol.CONN_PKT_KEM, pickle.dumps(signed_e2e_key))

        # Register the key afterwards, otherwise the recipient would need the key to decrypt the same key.
        self._conversations[conversation_id].shared_secret = kem_wrapped_shared_secret.decapsulated_key

    @LogPre
    # @ReplayErrorBackToUser
    def _handle_accept_connection(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        Handle an acceptance from a Node Y to connect to this Node X. Node X will have already sent a CONN_REQ to NODE
        Y; thus it stands that Node Y will always come after Node X in the route.
        :param addr:
        :return:
        """

        logging.debug(f"\t\tAccepting connection from: {addr.ip}")
        logging.debug(f"\t\tConnection token: {connection_token}")

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

        logging.debug(f"\t\tShared secret (CON): {self._conversations[conversation_id].shared_secret.raw[:100]}...")

    @LogPre
    def _handle_accept_connection_attach_key_to_client(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        current_final_node = [node for node in self._my_route.route if node.connection_token.address != self._pending_node_to_add_to_route][-1]
        current_final_node_static_public_key = DHT.get_static_public_key(current_final_node.connection_token.address.ip)

        my_static_private_key, my_static_public_key = KeyPair().import_("./_keys/me", "static").both()
        their_static_public_key = DHT.get_static_public_key(self._pending_node_to_add_to_route.ip)
        signed_e2e_pub_key = pickle.loads(data)

        logging.debug(f"\t\tTheir signed e2e public key: {hashlib.md5(signed_e2e_pub_key.signature.raw).hexdigest()}...")
        logging.debug(f"\t\tTheir e2e public key: {hashlib.md5(signed_e2e_pub_key.message.raw).hexdigest()}...")

        DigitalSigning.verify(
            their_static_public_key=their_static_public_key,
            signed_message=signed_e2e_pub_key,
            my_id=current_final_node_static_public_key)

        candidates = [c.address for c in self._conversations.keys() if c.token == connection_token and c.address != addr]
        assert len(candidates) == 1, f"There should be exactly one candidate, but there are {len(candidates)}: {candidates}"
        target_node = candidates[0]

        logging.debug(f"\t\t[1] Sending e2e public key to: {target_node.ip}")

        # Wait for the CONN_ACC to register the shared secret in another thread.
        conversation_id = ConnectionToken(token=connection_token, address=addr)
        while True:
            if conversation_id in self._conversations and self._conversations[conversation_id].state & ControlConnectionState.CONNECTED:
                break

        logging.debug(f"\t\t[2] Sending e2e public key to: {target_node.ip}")
        self._tunnel_message_backward(target_node, connection_token, ControlConnectionProtocol.CONN_EXT_ACC, pickle.dumps(signed_e2e_pub_key))

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
            self._send_message_onwards(target_node, connection_token, ControlConnectionProtocol.CONN_EXT_REJ, data)

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
        target_addr = pickle.loads(data)
        target_static_public_key = DHT.get_static_public_key(target_addr.ip)
        logging.debug(f"\t\tExtending to: {target_addr.ip}")

        # Create an ephemeral public key, sign it, and send it to the next node in the route. This establishes e2e
        # encryption over the connection.
        my_static_private_key = KeyPair().import_("./_keys/me", "static").secret_key
        my_ephemeral_private_key, my_ephemeral_public_key = KEM.generate_key_pair().both()

        logging.debug(f"\t\tGenerated ephemeral public key: {my_ephemeral_public_key.raw[:100]}...")
        logging.debug(f"\t\tGenerated ephemeral secret key: {my_ephemeral_private_key.raw[:100]}...")

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

        logging.debug(f"\t\tSigned ephemeral public key: {signed_my_ephemeral_public_key.signature.raw[:100]}...")

        sending_data = pickle.dumps(signed_my_ephemeral_public_key)
        self._send_message_onwards(target_addr, connection_token, ControlConnectionProtocol.CONN_REQ, sending_data)

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

        logging.debug(f"\t\tConfirming route extension to: {self._pending_node_to_add_to_route.ip}")
        logging.debug(f"\t\tConnection token: {connection_token}")
        logging.debug(f"\t\tData: {data[:100]}...")

        # If this is the client node accepting the extension to the route, add the node to the route list.
        if self._my_route and self._my_route.connection_token.token == connection_token:
            # Get the signed ephemeral public key from the data, and verify the signature. The key from Node Z was
            # originally sent to Node Y, so the identifier of Node Y is used to verify the signature.
            current_final_node = [node for node in self._my_route.route if node.connection_token.address != self._pending_node_to_add_to_route][-1]
            current_final_node_static_public_key = DHT.get_static_public_key(current_final_node.connection_token.address.ip)

            their_static_public_key = DHT.get_static_public_key(self._pending_node_to_add_to_route.ip)
            signed_ephemeral_public_key: SignedMessage = pickle.loads(data)

            # Log the signed ephemeral public key.
            logging.debug(f"\t\tAdded to route: {self._pending_node_to_add_to_route.ip}")
            logging.debug(f"\t\tTheir ephemeral public key: {signed_ephemeral_public_key.message.raw[:100]}...")
            logging.debug(f"\t\tTheir signed ephemeral public key: {signed_ephemeral_public_key.signature.raw[:100]}...")

            # Verify the signature of the ephemeral public key being sent from the accepting node.
            DigitalSigning.verify(
                their_static_public_key=their_static_public_key,
                signed_message=signed_ephemeral_public_key,
                my_id=current_final_node_static_public_key)

            # Check that the command (signed by the target node being extended to), is indeed what the next node
            # reported. This is to prevent the next node lying about the state of the connection. If the next node is
            # lying, this node needs changing. TODO: Remove lying node
            # target_cmd, target_connection_token, data = self._parse_message(signed_ephemeral_public_key.message.raw)
            # assert target_cmd == ControlConnectionProtocol.CONN_EXT_ACC
            # assert target_connection_token == connection_token todo : what was this for?

            # Verify the signature of the ephemeral public key being sent from the accepting node.
            DigitalSigning.verify(
                their_static_public_key=their_static_public_key,
                signed_message=signed_ephemeral_public_key,
                my_id=current_final_node_static_public_key)

            # Save the connection information to the route list.
            self._my_route.route.append(ControlConnectionRouteNode(
                connection_token=ConnectionToken(token=connection_token, address=self._pending_node_to_add_to_route),
                ephemeral_key_pair=KeyPair(public_key=signed_ephemeral_public_key.message),
                shared_secret=None))
            kem_wrapped_packet_key = KEM.kem_wrap(signed_ephemeral_public_key.message)

            # Note: vulnerable to MITM, so use unilateral authentication later. TODO
            logging.debug(f"\t\tSending packet key to: {self._pending_node_to_add_to_route.ip}")
            self._tunnel_message_forwards(self._pending_node_to_add_to_route, connection_token, ControlConnectionProtocol.CONN_PKT_KEY, kem_wrapped_packet_key.encapsulated_key.raw)

            # The shared secret is added here. If added before, the recipient would need the key to decrypt the key.
            self._my_route.route[-1].shared_secret = kem_wrapped_packet_key

            logging.debug(f"\t\tShared secret (PKT) {self._my_route.route[-1].shared_secret.decapsulated_key.raw[:100]}...")

        # Otherwise, send this message to the previous node in the route.
        else:
            candidates = [c.address for c in self._conversations.keys() if c.token == connection_token and c.address != addr]
            assert len(candidates) == 1
            target_node = candidates[0]
            self._send_message_onwards(target_node, connection_token, ControlConnectionProtocol.CONN_EXT_ACC, data)

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
            self._send_message_onwards(target_node, connection_token, ControlConnectionProtocol.CONN_EXT_REJ, data)

    @LogPre
    def _handle_packet_key(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        logging.debug(f"\t\tReceived KEM-wrapped packet key from: {addr.ip}")
        logging.debug(f"\t\tConnection token: {connection_token}")

        my_ephemeral_secret_key = self._node_to_client_tunnel_keys[connection_token].ephemeral_key_pair.secret_key
        self._node_to_client_tunnel_keys[connection_token].shared_secret = KEM.kem_unwrap(my_ephemeral_secret_key, SecureBytes(data))
        logging.debug(f"\t\tShared secret (PKT): {self._node_to_client_tunnel_keys[connection_token].shared_secret.decapsulated_key.raw[:100]}...")

        self._tunnel_message_backward(addr, connection_token, ControlConnectionProtocol.CONN_PKT_ACK, b"")

    @LogPre
    def _handle_packet_key_ack(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        logging.debug(f"\t\tReceived packet key ACK from: {addr.ip}")
        logging.debug(f"\t\tConnection token: {connection_token}")

        conversation_id = ConnectionToken(token=connection_token, address=self._pending_node_to_add_to_route)
        self._conversations[conversation_id].state |= ControlConnectionState.SECURE
        logging.debug(f"\t\tConnection flags: {self._conversations[conversation_id].state}")

    @LogPre
    # @ReplayErrorBackToUser
    def _forward_message(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:  # TODO: bug in here (address)
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
        # assert len(candidates) == 1, f"There should be exactly one candidate, but there are {len(candidates)}: {candidates}"
        if not candidates:
            candidates = [Address.me()]
        target_node = candidates[0]

        logging.debug(f"\t\t[F] Connection token: {connection_token}")
        logging.debug(f"\t\t[F] Raw payload ({len(data)}): {data[:100]}...")

        # Get the next command and data from the message, and send it to the target node. The "next_data" may still be
        # ciphertext if the intended target isn't the next node (could be the node after that), with multiple nested
        # messages of "CONN_FWD" commands.
        # next_command, next_connection_token, next_data = self._parse_message(data)
        # assert next_connection_token == connection_token

        # logging.debug(f"\t\t[F] Next command: {next_command}")
        # logging.debug(f"\t\t[F] Next data: {next_data[:100]}...")
        # logging.debug(f"\t\t[F] Forwarding message to: {target_node.ip}")

        # Send the message to the target node. It will be automatically encrypted.
        self._send_message_onwards_raw(target_node, connection_token, data)

    @LogPre
    def _tunnel_message_forwards(self, addr: Address, connection_token: Bytes, command: ControlConnectionProtocol, data: Bytes) -> None:
        logging.debug(f"\t\tTunneling {command} to: {addr.ip}")
        logging.debug(f"\t\tConnection token: {connection_token}")
        logging.debug(f"\t\tRaw payload: {data[:100]}...")

        # Encrypt per layer until the node in the route == the node that the data is being sent to.
        if self._my_route and self._my_route.connection_token.token == connection_token:
            route_node_addresses = [n.connection_token.address for n in self._my_route.route]
            target_node_route_index = route_node_addresses.index(addr) if addr in route_node_addresses else -1

            if target_node_route_index > -1:
                relay_nodes = list(reversed(self._my_route.route[1:target_node_route_index + 1]))
            else:
                relay_nodes = list(reversed(self._my_route.route[1:]))

            logging.debug(f"\t\tTunneling via {[n.connection_token.address.ip for n in relay_nodes]}")

            # Combine the data components (this data will be sent to "self" and forwarded on)
            data = command.value.to_bytes(1, "big") + connection_token + data

            # For each node in the path until the target node, apply a layer of encryption.
            for next_node in relay_nodes:
                logging.debug(f"\t\tLayering through & including: {next_node.connection_token.address.ip}")

                # No shared secret when exchanging the KEM for the shared secret.
                if next_node.shared_secret:
                    data = SymmetricEncryption.encrypt(SecureBytes(data), next_node.shared_secret.decapsulated_key).raw
                    logging.debug(f"\t\tTunnel encrypted payload: {data[:100]}...")

                data = ControlConnectionProtocol.CONN_FWD.value.to_bytes(1, "big") + next_node.connection_token.token + data
                logging.debug(f"\t\tForward-wrapped encrypted payload: {data[:100]}...")

            if relay_nodes:
                command, _, data = self._parse_message(data)
            else:
                command, data = ControlConnectionProtocol.CONN_FWD, data

        self._send_message_onwards(self._my_route.route[0].connection_token.address, connection_token, command, data)

    @LogPre
    def _tunnel_message_backward(self, addr: Address, connection_token: Bytes, command: ControlConnectionProtocol, data: Bytes) -> None:
        # Encrypt with 1 layer as this message is travelling backwards to the client node. Don't do this for sending
        # information to self.
        if not (self._my_route and self._my_route.connection_token.token == connection_token):
            data = command.value.to_bytes(1, "big") + connection_token + data
            if shared_secret := self._node_to_client_tunnel_keys[connection_token].shared_secret:
                client_key = shared_secret.decapsulated_key
                data = SymmetricEncryption.encrypt(SecureBytes(data), client_key).raw
            data = ControlConnectionProtocol.CONN_FWD.value.to_bytes(1, "big") + connection_token + data
            self._send_message_onwards_raw(addr, connection_token, data)

        else:
            nested_command, nested_data = command, data
            relay_nodes = iter(self._my_route.route[1:])
            while nested_command == ControlConnectionProtocol.CONN_FWD:
                relay_node_key = next(relay_nodes).shared_secret.decapsulated_key
                data = SymmetricEncryption.decrypt(SecureBytes(nested_data), relay_node_key).raw
                nested_command, nested_connection_token, nested_data = self._parse_message(data)
                assert nested_connection_token == connection_token

            self._handle_message(addr, nested_command, connection_token, nested_data)

    @LogPre
    def _send_message_onwards(self, addr: Address, connection_token: Bytes, command: ControlConnectionProtocol, data: Bytes) -> None:
        logging.debug(f"\t\tSending {command} to: {addr.ip}")
        logging.debug(f"\t\tConnection token: {connection_token}")
        logging.debug(f"\t\tRaw payload ({len(data)}): {data[:100]}...")

        data = command.value.to_bytes(1, "big") + connection_token + data
        self._send_message_onwards_raw(addr, connection_token, data)

    @LogPre
    def _send_message_onwards_raw(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        # Encrypt the connection to the direct neighbour node, if a shared secret has been established.
        conversation_id = ConnectionToken(token=connection_token, address=addr)
        if shared_secret := self._conversations[conversation_id].shared_secret:
            data = SymmetricEncryption.encrypt(SecureBytes(data), shared_secret).raw
            logging.debug(f"\t\tE2E encrypted payload: {data[:100]}...")

        # Send the data to the node.
        self._udp_server.udp_send(data, addr.socket_format())

    @LogPre
    def _recv_message(self, data: Bytes, raw_addr: Tuple[Str, Int]) -> None:
        logging.debug(f"\t\tReceived message from: {raw_addr[0]}")
        logging.debug(f"\t\tRaw payload: {data[:100]}...")

        addr = Address(ip=raw_addr[0], port=raw_addr[1])

        # Decrypt the e2e connection if its encrypted (not encrypted when initiating a connection).
        if addr in [c.address for c in self._conversations.keys()]:
            connection_token = [c.token for c in self._conversations.keys() if c.address == addr][0]
            conversation_id = ConnectionToken(token=connection_token, address=addr)
            if shared_secret := self._conversations[conversation_id].shared_secret:
                data = SymmetricEncryption.decrypt(SecureBytes(data), shared_secret).raw
                logging.debug(f"\t\tE2E decrypted payload: {data[:100]}...")

        # Decrypt any layered encryption (if the command is CONN_FWD).
        connection_token = [c.token for c in self._conversations.keys() if c.address == addr]

        # Decrypt all layers (this node is the client node). The exception is when this node has send this node data, as
        # at this point, the idea is to just execute the command on this node.
        # todo : just call "self._handle_message directly(...)", and remove the "addr != Address.me()"?
        if self._my_route and self._my_route.connection_token.token == connection_token[0]:
            if addr != Address.me():
                relay_nodes = iter(self._my_route.route[1:])
                next_node = next(relay_nodes, None)

                logging.debug(f"\t\tUnwrapping layers")
                # logging.debug(f"\t\tParsed command: {nested_command}")
                # logging.debug(f"\t\tParsed connection token: {nested_connection_token}...")
                # logging.debug(f"\t\tParsed data: {nested_data[:100]}...")

                nested_data = data
                while next_node:
                    data = nested_data
                    logging.debug(f"\t\tUnwrapping layer from {next_node.connection_token.address.ip}")

                    if next_node.shared_secret:
                        relay_node_key = next_node.shared_secret.decapsulated_key
                        data = SymmetricEncryption.decrypt(SecureBytes(data), relay_node_key).raw
                        logging.debug(f"\t\tDecrypted payload: {data[:100]}...")

                    nested_command, nested_connection_token, nested_data = self._parse_message(data)
                    assert nested_connection_token == connection_token[0]
                    next_node = next(relay_nodes, None)

        elif connection_token and self._node_to_client_tunnel_keys[connection_token[0]].shared_secret:
            two_nodes_with_connection_token = [c.address for c in self._conversations.keys() if c.token == connection_token[0]]
            from_previous_node = addr == two_nodes_with_connection_token[0]

            # Relay node receiving a message from the previous node in the route => decrypt a layer
            if from_previous_node:
                client_key = self._node_to_client_tunnel_keys[connection_token[0]].shared_secret.decapsulated_key
                data = SymmetricEncryption.decrypt(SecureBytes(data), client_key).raw
                logging.debug(f"\t\tDecrypted payload: {data[:100]}...")

            # Relay node receiving a message from the next node in the route => add a layer of encryption
            elif self._parse_message(data)[0] == ControlConnectionProtocol.CONN_FWD.value:
                client_key = self._node_to_client_tunnel_keys[connection_token[0]].shared_secret.decapsulated_key
                data = SymmetricEncryption.encrypt(SecureBytes(data), client_key).raw
                data = ControlConnectionProtocol.CONN_FWD.value.to_bytes(1, "big") + connection_token[0] + data
                data = ControlConnectionProtocol.CONN_FWD.value.to_bytes(1, "big") + connection_token[0] + data
                logging.debug(f"\t\tEncrypted payload: {data[:100]}...")

        # Parse and handle the message
        command, connection_token, data = self._parse_message(data)

        logging.debug(f"\t\tParsed command: {command}")
        logging.debug(f"\t\tParsed connection token: {connection_token}...")
        logging.debug(f"\t\tParsed data: {data[:100]}...")

        self._handle_message(addr, command, connection_token, data)

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
        return conversation_id in self._conversations.keys() and self._conversations[conversation_id].state & ControlConnectionState.WAITING_FOR_ACK

    def _is_connected_to(self, addr: Address, connection_token: Bytes) -> bool:
        conversation_id = ConnectionToken(token=connection_token, address=addr)
        return conversation_id in self._conversations.keys() and self._conversations[conversation_id].state & ControlConnectionState.CONNECTED

    def _is_in_route(self, addr: Address, connection_token: Bytes) -> bool:
        conversation_id = ConnectionToken(token=connection_token, address=addr)
        return self._my_route and conversation_id in [n.connection_token for n in self._my_route.route]


__all__ = ["ControlConnectionManager"]
