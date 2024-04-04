from __future__ import annotations

import json
import os.path
import socket
import logging, pickle
import time
from argparse import Namespace
from ipaddress import IPv4Address

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

from src.control_communications.ControlConnectionServer import *
from src.control_communications.ControlConnectionProtocol import *
from src.control_communications.ControlConnectionRoute import *
from src.control_communications.ControlConnectionConversation import *
from src.crypto_engines.crypto.DigitalSigning import DigitalSigning, SignedMessage
from src.crypto_engines.crypto.KeyEncapsulation import KEM
from src.crypto_engines.crypto.SymmetricEncryption import SymmetricEncryption
from src.crypto_engines.crypto.Hashing import Hashing
from src.crypto_engines.tools.KeyPair import KeyPair
from src.distributed_hash_table.DHT import DHT, NodeNotInNetworkException
from src.MyTypes import Bytes, Tuple, Str, Int, Dict, Optional


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
    def inner(self, *args, **kwargs):
        logging.info(f"ConnectionControlManager::{function.__name__}")
        return function(self, *args, **kwargs)
    return inner


class ControlConnectionManager:
    """
    The ControlConnectionManager handles all communications between this node and any other node in the network. It
    manages the creation of the route, the extension of the route, and the sending of messages to other nodes.

    Attributes
    - _udp_server: The UDP server for the control connection manager (wraps a socket).
    - _conversations: A list of conversations with neighbouring nodes, used for relay node connections.
    - _my_route: The list of nodes in the route from this client node.
    - _node_to_client_tunnel_keys: The tunnel keys from this node to client nodes that own routes this node is in.
    - _pending_node_to_add_to_route: The node that is pending to be added to the route.
    """

    _udp_server: ControlConnectionServer
    _conversations: Dict[ConnectionToken, ControlConnectionConversationInfo]
    _my_route: Optional[ControlConnectionRoute]
    _node_to_client_tunnel_keys: Dict[Bytes, ControlConnectionRouteNode]
    _pending_node_to_add_to_route: Optional[Address]
    _is_directory_node: bool
    _waiting_for_cert: bool

    def __init__(self, is_directory_node: bool = False, instant_routing: bool = False):
        # Setup the attributes of the control connection manager.
        self._udp_server = ControlConnectionServer()
        self._udp_server.on_message_received = self._recv_message

        self._conversations = {}
        self._my_route = None
        self._node_to_client_tunnel_keys = {}
        self._pending_node_to_add_to_route = None

        self._is_directory_node = is_directory_node
        self._waiting_for_cert = False

        # Setup functions that are optionally run depending on the state of this node.
        if not self._is_directory_node and not os.path.exists("./_certs/certificate.ctf"):
            self.obtain_certificate()

        if not self._is_directory_node and len(json.loads(open("./_cache/dht_cache.json").read())) == 0:
            self.obtain_first_nodes()

        # if not self._is_directory_node:
        #     self.refresh_cache()

    @LogPre
    def create_route(self, _arguments: Namespace) -> None:
        """
        Create a route where this node is the client node. This node will select nodes from the DHT and communicate to
        them via the existing route, maintaining anonymity. Only the entry node (node 1) knows who the client is.
        @param _arguments: The arguments from the command line.
        @return: None.
        """
        if self._my_route:
            return

        # To create the route, the client will tell itself to extend the connection to the first node in the route. Each
        # time a new node is added, the communication flows via every node in the existing network, so only the first
        # node in the route knows the client node.
        connection_token = ConnectionToken(token=os.urandom(32), address=Address.me())
        route_node = ControlConnectionRouteNode(connection_token=connection_token, ephemeral_key_pair=None, shared_secret=None, secure=False)
        self._my_route = ControlConnectionRoute(route=[route_node], connection_token=connection_token)

        # Add the conversation to myself
        self._conversations[connection_token] = ControlConnectionConversationInfo(
            state=ControlConnectionState.CONNECTED,
            their_static_public_key=KeyPair().import_("./_keys/me", "static").public_key,
            shared_secret=None,
            my_ephemeral_public_key=None,
            my_ephemeral_secret_key=None,
            secure=True)

        # Extend the connection (use a while loop so failed connections don't affect the node counter for route length).
        my_ip = Address.me().ip
        while len(self._my_route.route) < 4:
            # Extend the connection to the next node in the route.
            current_ips_in_route = [node.connection_token.address.ip for node in self._my_route.route]
            self._pending_node_to_add_to_route = Address(ip=DHT.get_random_node(current_ips_in_route + [my_ip])["ip"], port=12345)
            logging.info(f"\t\t\033[32mExtending route to: {self._pending_node_to_add_to_route.ip}\033[0m")

            self._tunnel_message_forwards(
                addr=self._pending_node_to_add_to_route,
                connection_token=connection_token.token,
                command=ControlConnectionProtocol.CONN_EXT,
                data=pickle.dumps(self._pending_node_to_add_to_route))

            while True:
                addresses = [node.connection_token.address for node in self._my_route.route]
                if self._pending_node_to_add_to_route in addresses and self._my_route.route[-1].secure:
                    break

        # Log the route.
        logging.info(f"\t\tCreated route: {' -> '.join([node.connection_token.address.ip for node in self._my_route.route])}")

    def obtain_certificate(self):
        # This is a new node, so generate a static asymmetric key pair for signing.
        static_asymmetric_key_pair = KeyPair().import_("./_keys/me", "static")

        # Create the connection to the directory node.
        connection_token = ConnectionToken(token=os.urandom(32), address=Address(ip=DHT.get_random_directory_node()))

        # Dummy conversation to allow the directory node to send a certificate.
        self._conversations[connection_token] = ControlConnectionConversationInfo(
            state=ControlConnectionState.WAITING_FOR_ACK,
            their_static_public_key=None,
            shared_secret=None,
            my_ephemeral_public_key=None,
            my_ephemeral_secret_key=None,
            secure=False)

        # Mark this node as waiting for a certificate, and send the request for a certificate to the directory node.
        self._waiting_for_cert = True
        self._send_message_onwards(
            addr=connection_token.address,
            connection_token=connection_token.token,
            command=ControlConnectionProtocol.DIR_REG,
            data=static_asymmetric_key_pair.public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo))

        while self._waiting_for_cert:
            pass

        del self._conversations[connection_token]

    def obtain_first_nodes(self):
        target_address = Address(ip=DHT.get_random_directory_node())
        connection_token = self._open_connection_to(target_address)
        time.sleep(2)
        self._send_message_onwards(target_address, connection_token.token, ControlConnectionProtocol.DIR_LST_REQ, b"")

        cache_path = "./_cache/dht_cache.json"
        while not os.path.exists(cache_path) or len(json.load(open(cache_path))) == 0:
            pass

    def _open_connection_to(self, addr: Address) -> ConnectionToken:
        my_static_private_key = KeyPair().import_("./_keys/me", "static").secret_key
        my_ephemeral_private_key, my_ephemeral_public_key = KEM.generate_key_pair().both()

        connection_token = ConnectionToken(token=os.urandom(32), address=addr)
        self._conversations[connection_token] = ControlConnectionConversationInfo(
            state=ControlConnectionState.WAITING_FOR_ACK,
            their_static_public_key=DHT.get_static_public_key(addr.ip),
            shared_secret=None,
            my_ephemeral_public_key=my_ephemeral_public_key,
            my_ephemeral_secret_key=my_ephemeral_private_key,
            secure=False)

        signed_my_ephemeral_public_key = DigitalSigning.sign(
            my_static_private_key=my_static_private_key,
            message=my_ephemeral_public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo),
            their_id=DHT.get_id(addr.ip))

        sending_data = pickle.dumps((signed_my_ephemeral_public_key, False))

        self._send_message_onwards(addr, connection_token.token, ControlConnectionProtocol.CONN_REQ, sending_data)
        while not self._conversations[connection_token].secure:
            pass

        return connection_token

    def refresh_cache(self):
        node_to_contact = DHT.get_random_node(block_list=[Address.me().ip])

        if not node_to_contact:
            logging.debug("No nodes online at the moment")
            return

        logging.debug(f"Refreshing cache from {node_to_contact['ip']}")
        target_address = Address(ip=node_to_contact["ip"])
        connection_token = self._open_connection_to(target_address)

        nodes = []
        for x in range(3):
            next_node = DHT.get_random_node(block_list=[node["ip"] for node in nodes])
            if not next_node: break
            nodes.append(next_node)
        sending_data = pickle.dumps(nodes)

        self._send_message_onwards(target_address, connection_token.token, ControlConnectionProtocol.DHT_EXH_ADR, sending_data)

    # @LogPre
    @staticmethod
    def _parse_message(data: Bytes) -> Tuple[ControlConnectionProtocol, Bytes, Bytes]:
        """
        Parse the message into a command, connection token, and data. The command is always 1-byte long (first byte),
        the connection token is always 32 bytes, and the rest of the bytes will be the message data, so get each part by
        splitting at fixed indexes.
        @param data: The message to parse.
        @return: The command, connection token and data.
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
        Handle a message from a node. The message is handled by the command, and conditions based on the connection
        status for a conversation matching the connection token.
        @param addr: The address of the node that sent the message.
        @param command: The command of the message.
        @param connection_token: The connection token of the message.
        @param data: The data of the message.
        @return: None.
        """

        waiting_for_ack = self._waiting_for_ack_from(addr, connection_token)
        connected = self._is_connected_to(addr, connection_token)
        they_are_directory_node = addr.ip in DHT.DIRECTORY_NODES.keys()

        # Decide on the function to call based on the command, and call it.
        match command:

            # Handle a connection request from another node, and prevent double requests from the same conversation.
            case ControlConnectionProtocol.CONN_REQ if not connected and not waiting_for_ack:
                self._handle_request_to_connect(addr, connection_token, data)

            # Handle a connection acceptance from a node that this node is waiting for an ACK from.
            case ControlConnectionProtocol.CONN_ACC if waiting_for_ack:
                self._handle_accept_connection(addr, connection_token, data)

            # Handle a connection rejection from a node that this node is waiting for an ACK from.
            case ControlConnectionProtocol.CONN_REJ if waiting_for_ack:
                self._handle_reject_connection(addr, connection_token, data)

            # Handle a connection close from a node that this node is waiting for an ACK from, or is connected to.
            case ControlConnectionProtocol.CONN_CLS if waiting_for_ack or connected:
                self._cleanup_connection(addr, connection_token)

            # Handle a connection extension command from a node that this node is connected to.
            case ControlConnectionProtocol.CONN_EXT if connected:
                self._handle_extend_connection(addr, connection_token, data)

            # Handle a connection extension acceptance from a node that this node has extended to (and therefore already
            # connected to).
            case ControlConnectionProtocol.CONN_EXT_ACC if connected:
                self._handle_accept_extended_connection(addr, connection_token, data)

            # Handle a connection extension rejection from a node that this node has extended to (and therefore already
            # connected to).
            case ControlConnectionProtocol.CONN_EXT_REJ if connected:
                self._handle_reject_extended_connection(addr, connection_token, data)

            # Handle a forwarding command, where the data is sent to other node with the same connection token as the
            # sending node.
            case ControlConnectionProtocol.CONN_FWD:
                self._forward_message(addr, connection_token, data)

            # Handle a confirmation that a connection is node secure from a node. REQ -> ACC -> SEC.
            case ControlConnectionProtocol.CONN_SEC:
                self._register_connection_as_secure(addr, connection_token, data)

            # Handle a KEM key being tunnelled backwards from a relay node to the route owner.
            case ControlConnectionProtocol.CONN_PKT_KEM if connected or waiting_for_ack:
                self._handle_accept_connection_attach_key_to_client(addr, connection_token, data)

            # Handle a KEM-wrapped symmetric key being tunnelled forwards to a relay node from the route owner.
            case ControlConnectionProtocol.CONN_PKT_KEY:
                self._handle_packet_key(addr, connection_token, data)

            # Handle a KEM-wrapped symmetric key acknowledgement being tunnelled backwards from a relay node to the
            # route owner.
            case ControlConnectionProtocol.CONN_PKT_ACK if connected:
                self._handle_packet_key_ack(addr, connection_token, data)

            # Handle the directory node sending a certificate to this node, allowing trusted authentication to other
            # nodes in the network.
            case ControlConnectionProtocol.DIR_CER if self._waiting_for_cert and they_are_directory_node:
                self._handle_certificate_from_directory_node(addr, connection_token, data)

            # Handle registering a new node to the network when this node is a directory node.
            case ControlConnectionProtocol.DIR_REG if self._is_directory_node:
                self._handle_register_node_to_directory_node(addr, connection_token, data)

            # Handle a node requesting a list of nodes to bootstrap from when this node is a directory node.
            case ControlConnectionProtocol.DIR_LST_REQ if self._is_directory_node and connected:
                self._handle_request_for_nodes_from_directory_node(addr, connection_token, data)

            # Handle a node requesting a new certificate from a directory node.
            # case ControlConnectionProtocol.DIR_CER_REQ if self._is_directory_node and connected:
            #     self._handle_request_for_certificate_from_directory_node(addr, connection_token, data)

            # Handle a response from the directory node with a list of nodes to bootstrap from.
            case ControlConnectionProtocol.DIR_LST_RES if they_are_directory_node and connected:
                self._handle_response_for_nodes_from_directory_node(addr, connection_token, data)

            # Handle a DHT request to exchange IP addresses with a neighbouring node.
            case ControlConnectionProtocol.DHT_EXH_REQ:
                self._handle_request_for_certificate(addr, connection_token, data)

            # Handle a response to a DHT request for a certificate.
            case ControlConnectionProtocol.DHT_EXH_RES:
                self._handle_response_for_certificate(addr, connection_token, data)

            # Handle a list of IP addresses from a neighbouring node.
            case ControlConnectionProtocol.DHT_EXH_ADR if connected:
                self._handle_exchange_ip_addresses(addr, connection_token, data)

            # Handle an ACK of IP addresses received from the exchange.
            case ControlConnectionProtocol.DHT_EXH_ACK if connected:
                self._handle_exchange_ack_ip_addresses(addr, connection_token, data)

            # Otherwise, log an error, ignore the message, and do nothing.
            case _:
                logging.error(f"\t\tUnknown command or invalid state: {command}")
                # logging.error(f"\t\t{addr.ip} {self._pending_node_to_add_to_route.ip}")
                logging.error(f"\t\tWaiting for ack?: {waiting_for_ack}")
                logging.error(f"\t\tConnected?: {connected}")

    @LogPre
    def _handle_request_to_connect(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        Handle a request from a node to connect to this node, forming an end to end UDP connection. The request will
        either be for DHT maintenance, or for a new connection to be formed in a route, in which case the node will
        always be from a node that will be before this node in the route.
        @param addr: The address of the node requesting this node to partake in a connection.
        @param connection_token: The connection token of the request.
        @param data: The data of the request (their signed ephemeral public key).
        @return: None.
        """

        conversation_id = ConnectionToken(token=connection_token, address=addr)
        self._conversations[conversation_id] = ControlConnectionConversationInfo(
            state=ControlConnectionState.CONNECTED,
            their_static_public_key=None,
            shared_secret=None,
            my_ephemeral_public_key=None,
            my_ephemeral_secret_key=None,
            secure=False)

        # Get their static public key from the DHT, and the parse the signed message.
        my_static_private_key, my_static_public_key = KeyPair().import_("./_keys/me", "static").both()
        try:
            their_static_public_key = DHT.get_static_public_key(addr.ip)

        # Wait for the certificate to be received from the directory node.
        except NodeNotInNetworkException:
            self._send_message_onwards(addr, connection_token, ControlConnectionProtocol.DHT_EXH_REQ, os.urandom(32))
            while (their_static_public_key := DHT.get_static_public_key(addr.ip, silent=True)) is None:
                pass

        self._conversations[conversation_id].their_static_public_key = their_static_public_key
        their_signed_ephemeral_public_key, for_route = pickle.loads(data)

        # Verify the signature of the ephemeral public key being sent from the requesting node.
        DigitalSigning.verify(
            their_static_public_key=their_static_public_key,
            signed_message=their_signed_ephemeral_public_key,
            my_id=open("./_keys/me/identifier.txt", "rb").read(),
            allow_stale=True)  # temporarily, because of the possible delay from the DHT_EXH_REQ request.

        # Create a shared secret with a KEM, using their ephemeral public key, and sign it.
        their_ephemeral_public_key = their_signed_ephemeral_public_key.message
        kem_wrapped_shared_secret  = KEM.kem_wrap(their_ephemeral_public_key)
        signed_kem_wrapped_shared_secret = DigitalSigning.sign(
            my_static_private_key=my_static_private_key,
            message=kem_wrapped_shared_secret.encapsulated_key,
            their_id=DHT.get_id(addr.ip))

        # logging.debug(f"\t\tTheir ephemeral public key: {their_ephemeral_public_key.raw[:100]}...")
        # logging.debug(f"\t\tShared secret (CON): {kem_wrapped_shared_secret.decapsulated_key.raw[:100]}...")
        # logging.debug(f"\t\tKEM-wrapped shared secret: {kem_wrapped_shared_secret.encapsulated_key.raw[:100]}...")
        # logging.debug(f"\t\tSigned KEM wrapped shared secret: {signed_kem_wrapped_shared_secret.signature.raw[:100]}...")

        signed_e2e_key = None
        if for_route:
            self._node_to_client_tunnel_keys[connection_token] = ControlConnectionRouteNode(
                connection_token=conversation_id,
                ephemeral_key_pair=KEM.generate_key_pair(),
                shared_secret=None,
                secure=False)

            signed_e2e_key = DigitalSigning.sign(
                message=self._node_to_client_tunnel_keys[connection_token].ephemeral_key_pair.public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo),
                my_static_private_key=my_static_private_key,
                their_id=DHT.get_id(addr.ip))

        # logging.debug(f"\t\tE2E public key: {hashlib.md5(signed_e2e_key.message.raw).hexdigest()}...")
        # logging.debug(f"\t\tSigned E2E public key: {hashlib.md5(signed_e2e_key.signature.raw).hexdigest()}...")

        # Save the connection information for the requesting node.

        # Send the signed KEM wrapped shared secret to the requesting node.
        self._send_message_onwards(addr, connection_token, ControlConnectionProtocol.CONN_ACC, pickle.dumps(signed_kem_wrapped_shared_secret))
        while not self._conversations[conversation_id].secure:
            pass

        self._conversations[conversation_id].shared_secret = kem_wrapped_shared_secret.decapsulated_key
        # self._conversations[conversation_id].secure = True

        if for_route:
            self._tunnel_message_backward(addr, connection_token, ControlConnectionProtocol.CONN_PKT_KEM, pickle.dumps(signed_e2e_key))

    @LogPre
    # @ReplayErrorBackToUser
    def _handle_accept_connection(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        Handle an acceptance from a Node Y to connect to this Node X. Node X will have already sent a CONN_REQ to NODE
        Y; thus it stands that Node Y will always come after Node X in the route.
        :param addr:
        :return:
        """

        # logging.debug(f"\t\tAccepting connection from: {addr.ip}")
        # logging.debug(f"\t\tConnection token: {connection_token}")

        # Get the signed KEM wrapped shared secret from the data, and verify the signature.
        my_static_private_key, my_static_public_key = KeyPair().import_("./_keys/me", "static").both()
        their_static_public_key = DHT.get_static_public_key(addr.ip)
        signed_kem_wrapped_shared_secret = pickle.loads(data)

        # Verify the signature of the KEM wrapped shared secret being sent from the accepting node.
        DigitalSigning.verify(
            their_static_public_key=their_static_public_key,
            signed_message=signed_kem_wrapped_shared_secret,
            my_id=open("./_keys/me/identifier.txt", "rb").read())

        # Save the connection information for the accepting node.
        conversation_id = ConnectionToken(token=connection_token, address=addr)
        my_ephemeral_public_key = self._conversations[conversation_id].my_ephemeral_public_key
        my_ephemeral_secret_key = self._conversations[conversation_id].my_ephemeral_secret_key

        # Confirm to the other node that the connection is now secure, and from now on to use E2E encryption.
        self._send_message_onwards(addr, connection_token, ControlConnectionProtocol.CONN_SEC, b"")

        # Save the "shared secret", so E2E encryption is now available in the send/recv functions.
        self._conversations[conversation_id] = ControlConnectionConversationInfo(
            state=ControlConnectionState.CONNECTED,
            their_static_public_key=their_static_public_key,
            shared_secret=KEM.kem_unwrap(my_ephemeral_secret_key, signed_kem_wrapped_shared_secret.message).decapsulated_key,
            my_ephemeral_public_key=my_ephemeral_public_key,
            my_ephemeral_secret_key=my_ephemeral_secret_key,
            secure=True)

        # logging.debug(f"\t\tShared secret (CON): {self._conversations[conversation_id].shared_secret.raw[:100]}...")

    @LogPre
    def _handle_accept_connection_attach_key_to_client(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        current_final_node = [node for node in self._my_route.route if node.connection_token.address != self._pending_node_to_add_to_route][-1]
        current_final_node_static_public_key = DHT.get_static_public_key(current_final_node.connection_token.address.ip)
        current_final_node_id = DHT.get_id(current_final_node.connection_token.address.ip)

        my_static_private_key, my_static_public_key = KeyPair().import_("./_keys/me", "static").both()
        their_static_public_key = DHT.get_static_public_key(self._pending_node_to_add_to_route.ip)
        signed_e2e_pub_key = pickle.loads(data)

        # logging.debug(f"\t\tTheir signed e2e public key: {hashlib.md5(signed_e2e_pub_key.signature.raw).hexdigest()}...")
        # logging.debug(f"\t\tTheir e2e public key: {hashlib.md5(signed_e2e_pub_key.message.raw).hexdigest()}...")

        DigitalSigning.verify(
            their_static_public_key=their_static_public_key,
            signed_message=signed_e2e_pub_key,
            my_id=current_final_node_id)

        candidates = [c.address for c in self._conversations.keys() if c.token == connection_token and c.address != addr]
        assert len(candidates) == 1, f"There should be exactly one candidate, but there are {len(candidates)}: {candidates}"
        target_node = candidates[0]

        # logging.debug(f"\t\t[1] Sending e2e public key to: {target_node.ip}")

        # logging.debug(f"\t\t[2] Sending e2e public key to: {target_node.ip}")
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
        target_id = DHT.get_id(target_addr.ip)
        # logging.debug(f"\t\tExtending to: {target_addr.ip}")

        # Create an ephemeral public key, sign it, and send it to the next node in the route. This establishes e2e
        # encryption over the connection.
        my_static_private_key = KeyPair().import_("./_keys/me", "static").secret_key
        my_ephemeral_private_key, my_ephemeral_public_key = KEM.generate_key_pair().both()

        # logging.debug(f"\t\tGenerated ephemeral public key: {my_ephemeral_public_key.raw[:100]}...")
        # logging.debug(f"\t\tGenerated ephemeral secret key: {my_ephemeral_private_key.raw[:100]}...")

        # Register the connection in the conversation list.
        conversation_id = ConnectionToken(token=connection_token, address=target_addr)
        self._conversations[conversation_id] = ControlConnectionConversationInfo(
            state=ControlConnectionState.WAITING_FOR_ACK,
            their_static_public_key=target_static_public_key,
            shared_secret=None,
            my_ephemeral_public_key=my_ephemeral_public_key,
            my_ephemeral_secret_key=my_ephemeral_private_key,
            secure=False)

        # Send the signed ephemeral public key to the next node, maintaining the connection token. The next node will
        # ultimately send an EXT_ACK command to acknowledge the extension.
        signed_my_ephemeral_public_key = DigitalSigning.sign(
            my_static_private_key=my_static_private_key,
            message=my_ephemeral_public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo),
            their_id=target_id)

        # logging.debug(f"\t\tSigned ephemeral public key: {signed_my_ephemeral_public_key.signature.raw[:100]}...")

        sending_data = pickle.dumps((signed_my_ephemeral_public_key, True))
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

        # logging.debug(f"\t\tConfirming route extension to: {self._pending_node_to_add_to_route.ip}")
        # logging.debug(f"\t\tConnection token: {connection_token}")
        # logging.debug(f"\t\tData: {data[:100]}...")

        # If this is the client node accepting the extension to the route, add the node to the route list.
        if self._my_route and self._my_route.connection_token.token == connection_token:
            # Get the signed ephemeral public key from the data, and verify the signature. The key from Node Z was
            # originally sent to Node Y, so the identifier of Node Y is used to verify the signature.
            current_final_node = [node for node in self._my_route.route if node.connection_token.address != self._pending_node_to_add_to_route][-1]
            current_final_node_static_public_key = DHT.get_static_public_key(current_final_node.connection_token.address.ip)
            current_final_node_id = DHT.get_id(current_final_node.connection_token.address.ip)

            their_static_public_key = DHT.get_static_public_key(self._pending_node_to_add_to_route.ip)
            signed_ephemeral_public_key: SignedMessage = pickle.loads(data)

            # Log the signed ephemeral public key.
            # logging.debug(f"\t\tAdded to route: {self._pending_node_to_add_to_route.ip}")
            # logging.debug(f"\t\tTheir ephemeral public key: {signed_ephemeral_public_key.message.raw[:100]}...")
            # logging.debug(f"\t\tTheir signed ephemeral public key: {signed_ephemeral_public_key.signature.raw[:100]}...")

            # Verify the signature of the ephemeral public key being sent from the accepting node.
            DigitalSigning.verify(
                their_static_public_key=their_static_public_key,
                signed_message=signed_ephemeral_public_key,
                my_id=current_final_node_id)

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
                my_id=current_final_node_id)

            # Save the connection information to the route list.
            self._my_route.route.append(ControlConnectionRouteNode(
                connection_token=ConnectionToken(token=connection_token, address=self._pending_node_to_add_to_route),
                ephemeral_key_pair=KeyPair(public_key=load_pem_public_key(signed_ephemeral_public_key.message)),
                shared_secret=None,
                secure=False))
            kem_wrapped_packet_key = KEM.kem_wrap(load_pem_public_key(signed_ephemeral_public_key.message))

            # Note: vulnerable to MITM, so use unilateral authentication later. TODO
            # logging.debug(f"\t\tSending packet key to: {self._pending_node_to_add_to_route.ip}")
            self._tunnel_message_forwards(
                self._pending_node_to_add_to_route,
                connection_token,
                ControlConnectionProtocol.CONN_PKT_KEY,
                kem_wrapped_packet_key.encapsulated_key)

            # The shared secret is added here. If added before, the recipient would need the key to decrypt the key.
            self._my_route.route[-1].shared_secret = kem_wrapped_packet_key

            # logging.debug(f"\t\tShared secret (PKT) {self._my_route.route[-1].shared_secret.decapsulated_key.raw[:100]}...")

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
            original_node_id = DHT.get_id(self._my_route.route[-1].connection_token.address.ip)
            rejection_message: SignedMessage = pickle.loads(data)

            # Verify the signature of the rejection message being sent from the rejecting node.
            DigitalSigning.verify(
                their_static_public_key=their_static_public_key,
                signed_message=rejection_message,
                my_id=original_node_id)

            # Check that the command (signed by the target node being extended to), is indeed what the next node
            # reported. This is to prevent the next node lying about the state of the connection. If the next node is
            # lying, this node needs changing. TODO: Remove lying node
            target_cmd, target_connection_token, rejection_data = self._parse_message(rejection_message.message)
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
        # logging.debug(f"\t\tReceived KEM-wrapped packet key from: {addr.ip}")
        # logging.debug(f"\t\tConnection token: {connection_token}")

        my_ephemeral_secret_key = self._node_to_client_tunnel_keys[connection_token].ephemeral_key_pair.secret_key
        self._node_to_client_tunnel_keys[connection_token].shared_secret = KEM.kem_unwrap(my_ephemeral_secret_key, data)
        # logging.debug(f"\t\tShared secret (PKT): {self._node_to_client_tunnel_keys[connection_token].shared_secret.decapsulated_key.raw[:100]}...")

        self._tunnel_message_backward(addr, connection_token, ControlConnectionProtocol.CONN_PKT_ACK, b"")

    @LogPre
    def _handle_packet_key_ack(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        # logging.debug(f"\t\tReceived packet key ACK from: {self._pending_node_to_add_to_route}")
        # logging.debug(f"\t\tConnection token: {connection_token}")
        self._my_route.route[-1].secure = True

    @LogPre
    def _handle_certificate_from_directory_node(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        The certificate is a SignedMessage from the directory node. The connection is already e2e encrypted &
        authenticated at this point, but the extra signature is needed, so it can be sent to other nodes to prove
        authenticity from the directory node.
        @param addr:
        @param connection_token:
        @param data:
        @return:
        """

        # logging.debug(f"\t\tReceived certificate from directory node: {addr.ip}")
        # logging.debug(f"\t\tConnection token: {connection_token}")

        # Extra (unnecessary) verification of the directory node's signature on the certificate.
        my_static_public_key = KeyPair().import_("./_keys/me", "static").public_key
        certificate: SignedMessage = pickle.loads(data)
        directory_node_static_public_key = DHT.DIRECTORY_NODES[addr.ip]

        DigitalSigning.verify(
            their_static_public_key=directory_node_static_public_key,
            signed_message=certificate,
            my_id=open("./_keys/me/identifier.txt", "rb").read())

        # Export the certificate to a file, and set the "waiting for certificate flag" to False.
        open(f"./_certs/certificate.ctf", "wb").write(data)
        self._waiting_for_cert = False

    @LogPre
    def _handle_register_node_to_directory_node(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        This directory node will generate a certificate for the new node, and send it to the new node. The certificate
        will be signed by the directory node, and will be used to authenticate the new node to other nodes in the
        network.
        @param addr: The address of the new node to register.
        @param connection_token:
        @param data: The static public key of the node to register.
        @return:
        """

        # logging.debug(f"\t\tRegistering new node to directory node: {addr.ip}")
        # logging.debug(f"\t\tConnection token: {connection_token}")
        # logging.debug(f"\t\tTheir static public key: {data[:100]}...")

        their_static_public_key = data  # todo: remove correspongin ex-pikcle.dumps

        # Save the new node's public key to the DHT, and generate a certificate for the new node.
        node_id = Hashing.hash(their_static_public_key)
        # DirectoryNodeFileManager.add_record(node_id.raw, their_static_public_key.raw)

        # Temporary conversation
        target_connection_token = ConnectionToken(address=addr, token=connection_token)
        self._conversations[target_connection_token] = ControlConnectionConversationInfo(
            state=ControlConnectionState.CONNECTED,
            their_static_public_key=None,
            shared_secret=None,
            my_ephemeral_public_key=None,
            my_ephemeral_secret_key=None,
            secure=False)

        # Generate the certificate for the new node, signing it with the directory node's private key.
        previous_certificate_hash = b"\x00" * Hashing.ALGORITHM.digest_size
        my_static_private_key = KeyPair().import_("./_keys/me", "static").secret_key
        my_ip = IPv4Address(socket.gethostbyname(socket.gethostname())).packed
        certificate = DigitalSigning.sign(
            message=my_ip + previous_certificate_hash + node_id + their_static_public_key,
            my_static_private_key=my_static_private_key,
            their_id=node_id)

        # Cache the key for the node
        DHT.cache_node_information(node_id, their_static_public_key, addr.ip)

        # Send the certificate to the new node.
        self._send_message_onwards(addr, connection_token, ControlConnectionProtocol.DIR_CER, pickle.dumps(certificate))

        del self._conversations[target_connection_token]

    @LogPre
    def _handle_request_for_nodes_from_directory_node(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        Send a list of nodes to the requesting node. The list will be a list of the node IDs, and the static public
        keys of the nodes. At this point, an authenticated e2e connection will have been setup, so no extra signature is
        needed.

        @param addr:
        @param connection_token:
        @param data:
        @return:
        """

        # Get the list of nodes from the DHT, and send it to the requesting node.
        nodes = []
        for x in range(3):
            next_node = DHT.get_random_node(block_list=[node["ip"] for node in nodes])
            if not next_node: break
            nodes.append(next_node)
        self._send_message_onwards(addr, connection_token, ControlConnectionProtocol.DIR_LST_RES, pickle.dumps(nodes))

    @LogPre
    def _handle_response_for_nodes_from_directory_node(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """

        @param addr:
        @param connection_token:
        @param data:
        @return:
        """

        nodes = pickle.loads(data)
        for node in nodes:
            DHT.cache_node_information(node["id"], node["key"], node["ip"])

    @LogPre
    def _handle_request_for_certificate(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        my_certificate = open(f"./_certs/certificate.ctf", "rb").read()

        signed_challenge = DigitalSigning.sign(
            message=data,
            my_static_private_key=KeyPair().import_("./_keys/me", "static").secret_key,
            their_id=DHT.get_id(addr.ip))

        sending_data = pickle.dumps((pickle.loads(my_certificate), signed_challenge))
        logging.debug(len(sending_data))
        self._send_message_onwards(addr, connection_token, ControlConnectionProtocol.DHT_EXH_RES, sending_data)

    @LogPre
    def _handle_response_for_certificate(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        logging.debug(len(data))
        their_certificate, signed_challenge = pickle.loads(data)

        their_certificate: SignedMessage
        signed_challenge: SignedMessage

        their_static_public_key = their_certificate.message[-DigitalSigning.PUB_PEM_SIZE:]
        their_id = their_certificate.message[4 + Hashing.DIGEST_SIZE:-DigitalSigning.PUB_PEM_SIZE]
        directory_node_ip = IPv4Address(their_certificate.message[:4]).compressed

        # Verify the certificate is legitimate (allow stale because it's a certificate).
        DigitalSigning.verify(
            their_static_public_key=DHT.DIRECTORY_NODES[directory_node_ip],
            signed_message=their_certificate,
            my_id=their_id,
            allow_stale=True)

        # Verify the signed challenge uses the key in the certificate. todo: check challenge value
        DigitalSigning.verify(
            their_static_public_key=load_pem_public_key(their_static_public_key),
            signed_message=signed_challenge,
            my_id=open("./_keys/me/identifier.txt", "rb").read())

        # Cache the node information.
        DHT.cache_node_information(
            node_id=their_id,
            node_public_key=their_static_public_key,
            ip_address=addr.ip)

    @LogPre
    def _handle_exchange_ip_addresses(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        This command is used to exchange IP addresses with a neighbouring node. The IP addresses are used to bootstrap
        the DHT, and to find other nodes in the network. The logic is the same as the response from a DIR_LIST_REQ
        command to the directory node, so just call that handler function.
        @param addr:
        @param connection_token:
        @param data:
        @return:
        """

        # Cache their data
        nodes = pickle.loads(data)
        for node in nodes:
            DHT.cache_node_information(node["id"], node["key"], node["ip"])

        # Get some random nodes
        nodes = []
        for x in range(3):
            next_node = DHT.get_random_node(block_list=[node["ip"] for node in nodes])
            if not next_node: break
            nodes.append(next_node)

        # Send the nodes back
        self._send_message_onwards(addr, connection_token, ControlConnectionProtocol.DHT_EXH_ACK, pickle.dumps(nodes))

    @LogPre
    def _handle_exchange_ack_ip_addresses(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:

        # Cache their data
        nodes = pickle.loads(data)
        for node in nodes:
            DHT.cache_node_information(node["id"], node["key"], node["ip"])

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

        # logging.debug(f"\t\t[F] Connection token: {connection_token}")
        # logging.debug(f"\t\t[F] Raw payload ({len(data)}): {data[:100]}...")

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
    def _register_connection_as_secure(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        logging.debug(f"Marking connection to {addr.ip} as secure")

        conversation_id = ConnectionToken(token=connection_token, address=addr)
        self._conversations[conversation_id].secure = True

    @LogPre
    def _tunnel_message_forwards(self, addr: Address, connection_token: Bytes, command: ControlConnectionProtocol, data: Bytes) -> None:
        # logging.debug(f"\t\tTunneling {command} to: {addr.ip}")
        # logging.debug(f"\t\tConnection token: {connection_token}")
        # logging.debug(f"\t\tRaw payload: {data[:100]}...")

        # Encrypt per layer until the node in the route == the node that the data is being sent to.
        if self._my_route and self._my_route.connection_token.token == connection_token:
            route_node_addresses = [n.connection_token.address for n in self._my_route.route]
            target_node_route_index = route_node_addresses.index(addr) if addr in route_node_addresses else -1

            if target_node_route_index > -1:
                relay_nodes = list(reversed(self._my_route.route[1:target_node_route_index + 1]))
            else:
                relay_nodes = list(reversed(self._my_route.route[1:]))

            # logging.debug(f"\t\tTunneling via {[n.connection_token.address.ip for n in relay_nodes]}")

            # Combine the data components (this data will be sent to "self" and forwarded on)
            data = command.value.to_bytes(1, "big") + connection_token + data

            # For each node in the path until the target node, apply a layer of encryption.
            for next_node in relay_nodes:
                # logging.debug(f"\t\tLayering through & including: {next_node.connection_token.address.ip}")

                # No shared secret when exchanging the KEM for the shared secret.
                if next_node.shared_secret:
                    data = SymmetricEncryption.encrypt(data, next_node.shared_secret.decapsulated_key)
                    # logging.debug(f"\t\tTunnel encrypted payload: {data[:100]}...")

                data = ControlConnectionProtocol.CONN_FWD.value.to_bytes(1, "big") + next_node.connection_token.token + data
                # logging.debug(f"\t\tForward-wrapped encrypted payload: {data[:100]}...")

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
                data = SymmetricEncryption.encrypt(data, client_key)
                # logging.debug(f"\t\tTunnel backward encrypted payload: {data[:100]}...")

            self._send_message_onwards(addr, connection_token, ControlConnectionProtocol.CONN_FWD, data)

        else:
            nested_command, nested_data = command, data
            relay_nodes = iter(self._my_route.route[1:])
            while nested_command == ControlConnectionProtocol.CONN_FWD:
                relay_node_key = next(relay_nodes).shared_secret.decapsulated_key
                data = SymmetricEncryption.decrypt(nested_data, relay_node_key)
                nested_command, nested_connection_token, nested_data = self._parse_message(data)
                assert nested_connection_token == connection_token

            self._handle_message(addr, nested_command, connection_token, nested_data)

    @LogPre
    def _send_message_onwards(self, addr: Address, connection_token: Bytes, command: ControlConnectionProtocol, data: Bytes) -> None:
        logging.debug(f"\t\tSending {command} to: {addr.ip}: {data[:50]}...")
        # logging.debug(f"\t\tConnection token: {connection_token}")
        # logging.debug(f"\t\tRaw payload ({len(data)}): {data[:100]}...")

        data = command.value.to_bytes(1, "big") + connection_token + data
        self._send_message_onwards_raw(addr, connection_token, data)

    @LogPre
    def _send_message_onwards_raw(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        # Encrypt the connection to the direct neighbour node, if a shared secret has been established.
        conversation_id = ConnectionToken(token=connection_token, address=addr)
        if shared_secret := self._conversations[conversation_id].shared_secret:
            data = SymmetricEncryption.encrypt(data, shared_secret)
            # logging.debug(f"\t\tE2E encrypted payload: {data[:100]}...")

        # Send the data to the node (prepend the connection token because encryption will hide it).
        data = connection_token + data
        self._udp_server.udp_send(data, addr.socket_format())

    @LogPre
    def _recv_message(self, data: Bytes, raw_addr: Tuple[Str, Int]) -> None:
        logging.debug(f"\t\tReceived message from: {raw_addr[0]}")
        # logging.debug(f"\t\tRaw payload: {data[:100]}...")

        addr = Address(ip=raw_addr[0], port=raw_addr[1])
        connection_token, data = data[:32], data[32:]

        # print("#" * 50)
        # print(f"connection_token {raw_addr[0]}: {connection_token}")
        # print("-" * 50)
        # print("known tokens:")
        # for c in self._conversations.keys():
        #     print(f"{c.address.ip}: {c.token}")
        # print("#" * 50)

        # Decrypt the e2e connection if its encrypted (not encrypted when initiating a connection).
        if connection_token in [c.token for c in self._conversations.keys()]:
            print("known")
            # connection_token = [c.token for c in self._conversations.keys() if c.address == addr][0]
            conversation_id = ConnectionToken(token=connection_token, address=addr)

            if shared_secret := self._conversations[conversation_id].shared_secret:
                print("decrypting")
                data = SymmetricEncryption.decrypt(data, shared_secret)
                # logging.debug(f"\t\tE2E decrypted payload: {data[:100]}...")

        # Decrypt any layered encryption (if the command is CONN_FWD).
        # connection_token = [c.token for c in self._conversations.keys() if c.address == addr]

        # Decrypt all layers (this node is the client node). The exception is when this node has send this node data, as
        # at this point, the idea is to just execute the command on this node.
        # todo : just call "self._handle_message directly(...)", and remove the "addr != Address.me()"?
        if not self._is_directory_node and self._my_route and self._my_route.connection_token.token == connection_token:
            if addr != Address.me():
                relay_nodes = iter(self._my_route.route[1:])
                next_node = next(relay_nodes, None)

                # logging.debug(f"\t\tUnwrapping layers")
                # logging.debug(f"\t\tParsed command: {nested_command}")
                # logging.debug(f"\t\tParsed connection token: {nested_connection_token}...")
                # logging.debug(f"\t\tParsed data: {nested_data[:100]}...")

                while next_node:
                    # logging.debug(f"\t\tUnwrapping layer from {next_node.connection_token.address.ip}")
                    nested_command, nested_connection_token, nested_data = self._parse_message(data)
                    assert nested_connection_token == connection_token
                    data = nested_data

                    if next_node.shared_secret:
                        relay_node_key = next_node.shared_secret.decapsulated_key
                        data = SymmetricEncryption.decrypt(data, relay_node_key)
                        # logging.debug(f"\t\tDecrypted payload: {data[:100]}...")

                    next_node = next(relay_nodes, None)

        elif (not self._is_directory_node
              and connection_token
              and connection_token in self._node_to_client_tunnel_keys.keys()
              and self._node_to_client_tunnel_keys[connection_token].shared_secret):

            two_nodes_with_connection_token = [c.address for c in self._conversations.keys() if c.token == connection_token]
            from_previous_node = addr == two_nodes_with_connection_token[0]

            # Relay node receiving a message from the previous node in the route => decrypt a layer
            if from_previous_node:
                client_key = self._node_to_client_tunnel_keys[connection_token].shared_secret.decapsulated_key
                data = SymmetricEncryption.decrypt(data, client_key)
                # logging.debug(f"\t\tDecrypted payload: {data[:100]}...")

            # Relay node receiving a message from the next node in the route => add a layer of encryption
            elif self._parse_message(data)[0] == ControlConnectionProtocol.CONN_FWD:
                client_key = self._node_to_client_tunnel_keys[connection_token].shared_secret.decapsulated_key
                data = SymmetricEncryption.encrypt(data, client_key)
                data = ControlConnectionProtocol.CONN_FWD.value.to_bytes(1, "big") + connection_token + data

                prev_node = two_nodes_with_connection_token[0]
                self._send_message_onwards_raw(prev_node, connection_token, data)
                return

                # logging.debug(f"\t\tEncrypted payload: {data[:100]}...")

        # Parse and handle the message
        command, connection_token, data = self._parse_message(data)

        logging.debug(f"\t\tParsed command: {command}")
        # logging.debug(f"\t\tParsed connection token: {connection_token}...")
        # logging.debug(f"\t\tParsed data: {data[:100]}...")

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


__all__ = ["ControlConnectionManager"]
