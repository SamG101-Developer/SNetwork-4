from __future__ import annotations

import json
import os.path
import random
import socket
import logging, pickle
import time
from argparse import Namespace
from ipaddress import IPv4Address

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

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
from src.MyTypes import Bytes, Tuple, Str, Int, Dict, Optional, List
from src.packet_management.PacketInterceptor2 import ClientPacketInterceptor, IntermediaryNodeInterceptor


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
    _closer_nodes_to_files_resp: Dict[Tuple[Bytes, Bytes], Optional[Address]]
    _broker_node_files: Dict[Str, Bytes]
    _broker_node_file_requesters: Dict[Str, ConnectionToken]

    _routes_next_nodes: Dict[Bytes, Address]
    _routes_prev_nodes: Dict[Bytes, Address]
    _exit_node_broker_node_mapper: Dict[Bytes, ConnectionToken]

    _client_packet_interceptor: Optional[ClientPacketInterceptor]
    _intermediary_node_interceptor: Optional[IntermediaryNodeInterceptor]

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

        self._closer_nodes_to_files_resp = {}
        self._broker_node_files = {}
        self._broker_node_file_requesters = {}

        self._routes_next_nodes = {}
        self._routes_prev_nodes = {}
        self._exit_node_broker_node_mapper = {}

        self._client_packet_interceptor = None
        self._intermediary_node_interceptor = IntermediaryNodeInterceptor() if not self._is_directory_node else None

        # Check own information is in the cache
        if not self._is_directory_node:
            if not DHT.get_static_public_key(Address.me().ip, silent=True):
                my_static_public_key = KeyPair().import_("./_keys/me", "static").public_key
                my_id = bytes.fromhex(open("./_keys/me/identifier.txt", "r").read())
                DHT.cache_node_information(
                    node_id=my_id,
                    node_public_key=my_static_public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo),
                    ip_address=Address.me().ip)

        # Setup functions that are optionally run depending on the state of this node.
        if not self._is_directory_node and not os.path.exists("./_certs/certificate.ctf"):
            self._obtain_certificate()

        if not self._is_directory_node and len(json.loads(open("./_cache/dht_cache.json").read())) == 0:
            self._obtain_first_nodes()

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

        # Only allow 1 route to be created at a time.
        if self._my_route:
            return

        # To create the route, the client will tell itself to extend the connection to the first node in the route. Each
        # time a new node is added, the communication flows via every node in the existing network, so only the first
        # node in the route knows the client node.
        connection_token = ConnectionToken(token=os.urandom(32), address=Address.me())
        route_node = ControlConnectionRouteNode(connection_token=connection_token, ephemeral_key_pair=None, shared_secret=None, secure=False)
        self._my_route = ControlConnectionRoute(route=[route_node], connection_token=connection_token)

        # Create the packet interceptor for the client node.
        self._client_packet_interceptor = ClientPacketInterceptor(connection_token=connection_token.token)

        # Add the conversation to myself
        self._conversations[connection_token] = ControlConnectionConversationInfo(
            state=ControlConnectionState.CONNECTED,
            their_static_public_key=KeyPair().import_("./_keys/me", "static").public_key,
            shared_secret=os.urandom(32),
            my_ephemeral_public_key=None,
            my_ephemeral_secret_key=None,
            secure=True)

        # Check this node knows at least 3 other nodes in the network.
        if DHT.total_nodes_known([Address.me().ip]) < 3:
            logging.error("Not enough nodes in the network to create a route.")
            logging.debug("Refreshing cache...")
            self._refresh_cache()

            while DHT.total_nodes_known([Address.me().ip]) < 3:
                time.sleep(1)  # use "sleep" because file locks

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
        logging.info(f"\t\tHosting stored files...")

        for file_name in os.listdir("./_files/stored"):
            self.store_file("./_files/stored", file_name)

    def _obtain_certificate(self):
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
            data=static_asymmetric_key_pair.public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo))

        # Wait for the certificate
        while self._waiting_for_cert:
            pass

        # Remove the conversation from the list of conversations.
        del self._conversations[connection_token]

    def _obtain_first_nodes(self, need_to_know: List[Str] = None):
        # Connect to the directory node to get the first nodes to bootstrap from.
        target_address = Address(ip=DHT.get_random_directory_node())
        connection_token = self._open_connection_to(target_address)
        time.sleep(2)

        # Send the request for a list of nodes to bootstrap from.
        need_to_know_nodes = ",".join([node for node in need_to_know]) if need_to_know else ""
        self._send_message_onwards(target_address, connection_token.token, ControlConnectionProtocol.DIR_LST_REQ, need_to_know_nodes.encode())

        # Wait for the response from the directory node.
        cache_path = "./_cache/dht_cache.json"
        while not os.path.exists(cache_path):  # todo: is this loop needed?
            pass

    def _open_connection_to(self, addr: Address, token: bytes = b"") -> ConnectionToken:
        my_static_private_key = KeyPair().import_("./_keys/me", "static").secret_key
        my_ephemeral_private_key, my_ephemeral_public_key = KEM.generate_key_pair().both()

        connection_token = ConnectionToken(token=token or os.urandom(32), address=addr)
        self._conversations[connection_token] = ControlConnectionConversationInfo(
            state=ControlConnectionState.WAITING_FOR_ACK,
            their_static_public_key=DHT.get_static_public_key(addr.ip),
            shared_secret=None,
            my_ephemeral_public_key=my_ephemeral_public_key,
            my_ephemeral_secret_key=my_ephemeral_private_key,
            secure=False)

        signed_my_ephemeral_public_key = DigitalSigning.sign(
            my_static_private_key=my_static_private_key,
            message=my_ephemeral_public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo),
            their_id=DHT.get_id(addr.ip))

        sending_data = pickle.dumps((signed_my_ephemeral_public_key, False))

        self._send_message_onwards(addr, connection_token.token, ControlConnectionProtocol.CONN_REQ, sending_data)
        while not self._conversations[connection_token].secure:
            pass

        return connection_token

    def _refresh_cache(self):
        node_to_contact = DHT.get_random_node(block_list=[Address.me().ip])

        if not node_to_contact:
            logging.error("No nodes online at the moment")
            logging.debug("Using directory node")
            self._obtain_first_nodes()
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

    def store_file(self, file_directory: Str, file_name: Str) -> None:
        # Copy the file into the "_files/stored" folder (for access from other nodes)
        if file_directory != "./_files/stored":
            open(f"./_files/stored/{file_name}", "wb").write(open(os.path.join(file_directory, file_name), "rb").read())

        # Hash the file name to get the file tag, and determine the closest node.
        file_name += ".0"
        file_tag = Hashing.hash(file_name.encode())
        closest_node = DHT.closest_node_to(file_tag)

        logging.debug(f"\t\tFile name: {file_name}")
        logging.debug(f"\t\tFile tag: {file_tag}")
        logging.debug(f"\t\tClosest node to file tag: {closest_node}")

        # If this client node is the closest node, salt the file name until this node isn't the closest node.
        while closest_node in [node.connection_token.address.ip for node in self._my_route.route] + [Address.me().ip]:
            file_name += f"{random.randint(0, 9)}"
            file_tag = Hashing.hash(file_name.encode())
            closest_node = DHT.closest_node_to(file_tag)

            logging.debug(f"\t\tSalting to rotate closest node")
            logging.debug(f"\t\tNew File name: {file_name}")
            logging.debug(f"\t\tNew File tag: {file_tag}")
            logging.debug(f"\t\tClosest node to file tag: {closest_node}")

        # Continuously ask the "closest_node" for a closer node, if they know one.
        while True:
            # Open a connection to the current closest node, and send a request for a closer node to a hash.
            connection_token = self._open_connection_to(Address(ip=closest_node))
            self._closer_nodes_to_files_resp[(connection_token.token, file_tag)] = None
            self._send_message_onwards(Address(ip=closest_node), connection_token.token, ControlConnectionProtocol.DHT_CLOSER_NODES_REQ, file_tag)
            logging.debug("\t\tLooking for closer nodes to file tag...")

            # Wait until an IP address has been set to the dictionary based on the connection token and file tag.
            while not self._closer_nodes_to_files_resp[(connection_token.token, file_tag)]:
                pass

            # If the new closest node is the same as the current one, this is the true closest node.
            if self._closer_nodes_to_files_resp[(connection_token.token, file_tag)].ip == closest_node:
                logging.debug(f"\t\t{closest_node} is the closest node to the file tag.")
                break

            # Otherwise, send the request to the new closest node.
            closest_node = self._closer_nodes_to_files_resp[(connection_token.token, file_tag)].ip

        # Send a broker node request to the final node who will connect to and advertise to the broker node.
        self._tunnel_message_forwards(
            addr=self._my_route.route[-1].connection_token.address,
            connection_token=self._my_route.connection_token.token,
            command=ControlConnectionProtocol.DHT_SEND_BROKER_REQ,
            data=pickle.dumps((file_name, Address(ip=closest_node))))

        logging.debug(f"\t\tSent 'send broker node' request to {closest_node}")

    def retrieve_file(self, file_name: Str) -> None:
        # Hash the file name to get the file tag, and determine the closest node.
        file_tag = Hashing.hash(file_name.encode())
        broker_node = Address(ip=DHT.closest_node_to(file_tag))

        logging.debug(f"\t\tRetrieving file name: {file_name}")
        logging.debug(f"\t\tRetrieving from {broker_node}")

        # Send a request to the broker node to get the file.
        self._tunnel_message_forwards(
            addr=self._my_route.route[-1].connection_token.address,
            connection_token=self._my_route.connection_token.token,
            command=ControlConnectionProtocol.DHT_FILE_GET_FROM_BROKER,
            data=pickle.dumps((file_name, broker_node)))

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
            # case ControlConnectionProtocol.CONN_SEC:
            #     self._register_connection_as_secure(addr, connection_token, data)

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

            # Handle a request for closer nodes to a key.
            case ControlConnectionProtocol.DHT_CLOSER_NODES_REQ if connected:
                self._handle_request_for_closer_nodes(addr, connection_token, data)

            # Handle a response to a request for closer nodes to a key.
            case ControlConnectionProtocol.DHT_CLOSER_NODES_RES if connected:
                self._handle_response_for_closer_nodes(addr, connection_token, data)

            # Handle a command to send an advertisement to a broker node.
            case ControlConnectionProtocol.DHT_SEND_BROKER_REQ if connected:
                self._handle_send_dht_broker_request(addr, connection_token, data)

            # Handle an advertisement for a file (this node acting as a broke node)
            case ControlConnectionProtocol.DHT_ADV if connected:
                self._handle_dht_advertisement(addr, connection_token, data)

            # Handle a file being requested from a broker node.
            case ControlConnectionProtocol.DHT_FILE_GET_FROM_BROKER if connected:
                self._handle_dht_get_file_from_broker(addr, connection_token, data)

            # Handle a file being requested from a source node.
            case ControlConnectionProtocol.DHT_FILE_GET_FROM_SOURCE if connected:
                self._handle_dht_get_file_from_source(addr, connection_token, data)

            # Handle a file being sent to a broker node.
            case ControlConnectionProtocol.DHT_FILE_CONTENTS_TO_BROKER if connected:
                self._handle_dht_file_contents_to_broker(addr, connection_token, data)

            # Handle a file being sent to a client node.
            case ControlConnectionProtocol.DHT_FILE_CONTENTS_TO_CLIENT if connected:
                self._handle_dht_file_contents_to_client(addr, connection_token, data)

            # Otherwise, log an error, ignore the message, and do nothing.
            case _:
                logging.error(f"\t\tUnknown command or invalid state: {command}")
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

        # Save the connection information for the requesting node.
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
            my_id=bytes.fromhex(open("./_keys/me/identifier.txt", "r").read()),
            allow_stale=True)  # temporarily, because of the possible delay from the DHT_EXH_REQ request.

        # Create a shared secret with a KEM, using their ephemeral public key, and sign it.
        their_ephemeral_public_key = load_der_public_key(their_signed_ephemeral_public_key.message)
        kem_wrapped_shared_secret  = KEM.kem_wrap(their_ephemeral_public_key)
        signed_kem_wrapped_shared_secret = DigitalSigning.sign(
            my_static_private_key=my_static_private_key,
            message=kem_wrapped_shared_secret.encapsulated_key,
            their_id=DHT.get_id(addr.ip))

        # If this connection is for a route for another node, generate a client<->node tunnelling key.
        signed_e2e_key = None
        if for_route:
            self._routes_prev_nodes[connection_token] = addr
            self._node_to_client_tunnel_keys[connection_token] = ControlConnectionRouteNode(
                connection_token=conversation_id,
                ephemeral_key_pair=KEM.generate_key_pair(),
                shared_secret=None,
                secure=False)

            signed_e2e_key = DigitalSigning.sign(
                message=self._node_to_client_tunnel_keys[connection_token].ephemeral_key_pair.public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo),
                my_static_private_key=my_static_private_key,
                their_id=DHT.get_id(addr.ip))

        # Send the signed KEM wrapped shared secret to the requesting node.
        self._send_message_onwards(addr, connection_token, ControlConnectionProtocol.CONN_ACC, pickle.dumps(signed_kem_wrapped_shared_secret))
        # while not self._conversations[conversation_id].secure:
        #     pass

        self._conversations[conversation_id].shared_secret = kem_wrapped_shared_secret.decapsulated_key
        self._conversations[conversation_id].secure = True

        # Send the client<->node tunnelling key back along the route.
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

        # Get the signed KEM wrapped shared secret from the data, and verify the signature.
        my_static_private_key, my_static_public_key = KeyPair().import_("./_keys/me", "static").both()
        their_static_public_key = DHT.get_static_public_key(addr.ip)
        signed_kem_wrapped_shared_secret = pickle.loads(data)

        # Verify the signature of the KEM wrapped shared secret being sent from the accepting node.
        DigitalSigning.verify(
            their_static_public_key=their_static_public_key,
            signed_message=signed_kem_wrapped_shared_secret,
            my_id=bytes.fromhex(open("./_keys/me/identifier.txt", "r").read()))

        # Save the connection information for the accepting node.
        conversation_id = ConnectionToken(token=connection_token, address=addr)
        my_ephemeral_public_key = self._conversations[conversation_id].my_ephemeral_public_key
        my_ephemeral_secret_key = self._conversations[conversation_id].my_ephemeral_secret_key

        # Confirm to the other node that the connection is now secure, and from now on to use E2E encryption.
        # self._send_message_onwards(addr, connection_token, ControlConnectionProtocol.CONN_SEC, b"")

        # Save the "shared secret", so E2E encryption is now available in the send/recv functions.
        self._conversations[conversation_id] = ControlConnectionConversationInfo(
            state=ControlConnectionState.CONNECTED,
            their_static_public_key=their_static_public_key,
            shared_secret=KEM.kem_unwrap(my_ephemeral_secret_key, signed_kem_wrapped_shared_secret.message).decapsulated_key,
            my_ephemeral_public_key=my_ephemeral_public_key,
            my_ephemeral_secret_key=my_ephemeral_secret_key,
            secure=True)

    @LogPre
    def _handle_accept_connection_attach_key_to_client(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        # Get the final confirmed node in the route.
        current_final_node = [node for node in self._my_route.route if node.connection_token.address != self._pending_node_to_add_to_route][-1]
        current_final_node_static_public_key = DHT.get_static_public_key(current_final_node.connection_token.address.ip)
        current_final_node_id = DHT.get_id(current_final_node.connection_token.address.ip)

        my_static_private_key, my_static_public_key = KeyPair().import_("./_keys/me", "static").both()
        their_static_public_key = DHT.get_static_public_key(self._pending_node_to_add_to_route.ip)
        signed_e2e_pub_key = pickle.loads(data)

        DigitalSigning.verify(
            their_static_public_key=their_static_public_key,
            signed_message=signed_e2e_pub_key,
            my_id=current_final_node_id)

        candidates = [c.address for c in self._conversations.keys() if c.token == connection_token and c.address != addr]
        assert len(candidates) == 1, f"There should be exactly one candidate, but there are {len(candidates)}: {candidates}"
        target_node = candidates[0]

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
        target_static_public_key = DHT.get_static_public_key(target_addr.ip, silent=True)
        self._routes_next_nodes[connection_token] = target_addr

        # If the target node is not in the DHT, request the node information from the directory node.
        if not target_static_public_key:
            logging.error(f"\t\tTarget node for extension not in DHT: {target_addr.ip}")
            logging.debug(f"\t\tRequesting node information from directory node...")

            self._obtain_first_nodes(need_to_know=[target_addr.ip])
            while not (target_static_public_key := DHT.get_static_public_key(target_addr.ip, silent=True)):
                pass

        target_id = DHT.get_id(target_addr.ip)

        # Create an ephemeral public key, sign it, and send it to the next node in the route. This establishes e2e
        # encryption over the connection.
        my_static_private_key = KeyPair().import_("./_keys/me", "static").secret_key
        my_ephemeral_private_key, my_ephemeral_public_key = KEM.generate_key_pair().both()

        # Register the connection in the conversation list.
        logging.debug(f"\t\tExtending connection with {connection_token}")
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
            message=my_ephemeral_public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo),
            their_id=target_id)

        sending_data = pickle.dumps((signed_my_ephemeral_public_key, True))
        self._send_message_onwards(target_addr, connection_token, ControlConnectionProtocol.CONN_REQ, sending_data)

        # while not self._conversations[conversation_id].secure:
        #     pass

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

        # If this is the client node accepting the extension to the route, add the node to the route list.
        if self._my_route and self._my_route.connection_token.token == connection_token:
            # Get the signed ephemeral public key from the data, and verify the signature. The key from Node Z was
            # originally sent to Node Y, so the identifier of Node Y is used to verify the signature.
            current_final_node = [node for node in self._my_route.route if node.connection_token.address != self._pending_node_to_add_to_route][-1]
            current_final_node_static_public_key = DHT.get_static_public_key(current_final_node.connection_token.address.ip)
            current_final_node_id = DHT.get_id(current_final_node.connection_token.address.ip)

            their_static_public_key = DHT.get_static_public_key(self._pending_node_to_add_to_route.ip)
            signed_ephemeral_public_key: SignedMessage = pickle.loads(data)

            # Verify the signature of the ephemeral public key being sent from the accepting node.
            DigitalSigning.verify(
                their_static_public_key=their_static_public_key,
                signed_message=signed_ephemeral_public_key,
                my_id=current_final_node_id)

            # Check that the command (signed by the target node being extended to), is indeed what the next node
            # reported. This is to prevent the next node lying about the state of the connection. If the next node is
            # lying, this node needs changing. TODO: Remove lying node

            # Verify the signature of the ephemeral public key being sent from the accepting node.
            DigitalSigning.verify(
                their_static_public_key=their_static_public_key,
                signed_message=signed_ephemeral_public_key,
                my_id=current_final_node_id)

            # Save the connection information to the route list.
            self._my_route.route.append(ControlConnectionRouteNode(
                connection_token=ConnectionToken(token=connection_token, address=self._pending_node_to_add_to_route),
                ephemeral_key_pair=KeyPair(public_key=load_der_public_key(signed_ephemeral_public_key.message)),
                shared_secret=None,
                secure=False))
            kem_wrapped_packet_key = KEM.kem_wrap(load_der_public_key(signed_ephemeral_public_key.message))

            # Note: vulnerable to MITM, so use unilateral authentication later. TODO
            # logging.debug(f"\t\tSending packet key to: {self._pending_node_to_add_to_route.ip}")
            self._tunnel_message_forwards(
                self._pending_node_to_add_to_route,
                connection_token,
                ControlConnectionProtocol.CONN_PKT_KEY,
                kem_wrapped_packet_key.encapsulated_key)

            # The shared secret is added here. If added before, the recipient would need the key to decrypt the key.
            self._my_route.route[-1].shared_secret = kem_wrapped_packet_key
            self._client_packet_interceptor.register_info(
                address=self._pending_node_to_add_to_route.ip,
                key=self._my_route.route[-1].shared_secret.decapsulated_key)

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
            # target_cmd, target_connection_token, rejection_data = self._parse_message(rejection_message.message)
            # assert target_cmd == ControlConnectionProtocol.CONN_EXT_REJ
            # assert target_connection_token == connection_token

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
        my_ephemeral_secret_key = self._node_to_client_tunnel_keys[connection_token].ephemeral_key_pair.secret_key
        self._node_to_client_tunnel_keys[connection_token].shared_secret = KEM.kem_unwrap(my_ephemeral_secret_key, data)

        # TODO: Hash and sign the key back, so the client can check for tampering
        self._tunnel_message_backward(addr, connection_token, ControlConnectionProtocol.CONN_PKT_ACK, b"")

        # Register the node with the intermediary node interceptor.
        self._intermediary_node_interceptor.register_prev_node(
            connection_token=connection_token,
            key=self._node_to_client_tunnel_keys[connection_token].shared_secret.decapsulated_key,
            previous_address=addr.ip)

    @LogPre
    def _handle_packet_key_ack(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
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

        # Extra (unnecessary) verification of the directory node's signature on the certificate.
        my_static_public_key = KeyPair().import_("./_keys/me", "static").public_key
        certificate: SignedMessage = pickle.loads(data)
        directory_node_static_public_key = DHT.DIRECTORY_NODES[addr.ip]

        DigitalSigning.verify(
            their_static_public_key=directory_node_static_public_key,
            signed_message=certificate,
            my_id=bytes.fromhex(open("./_keys/me/identifier.txt", "r").read()))

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

        their_static_public_key = data  # todo: remove correspongin ex-pikcle.dumps

        # Save the new node's public key to the DHT, and generate a certificate for the new node.
        node_id = Hashing.hash(their_static_public_key)

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

        # Parse the required addresses from the data.
        required_ip_addresses = data.split(b",") if data else []
        nodes = []

        # Get the fixed nodes first.
        for ip in required_ip_addresses:
            node = DHT.get_fixed_node(ip.decode())
            if node: nodes.append(node)

        # Get random nodes from the DHT.
        for x in range(min(3, 3 - len(nodes))):
            next_node = DHT.get_random_node(block_list=[node["ip"] for node in nodes])
            if not next_node: break
            nodes.append(next_node)

        # Send the nodes to the requesting node.
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
        self._send_message_onwards(addr, connection_token, ControlConnectionProtocol.DHT_EXH_RES, sending_data)

    @LogPre
    def _handle_response_for_certificate(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        their_certificate, signed_challenge = pickle.loads(data)

        their_certificate: SignedMessage
        signed_challenge: SignedMessage

        their_static_public_key = their_certificate.message[-DigitalSigning.PUB_DER_SIZE:]
        their_id = their_certificate.message[4 + Hashing.DIGEST_SIZE:-DigitalSigning.PUB_DER_SIZE]
        directory_node_ip = IPv4Address(their_certificate.message[:4]).compressed

        # Verify the certificate is legitimate (allow stale because it's a certificate).
        DigitalSigning.verify(
            their_static_public_key=DHT.DIRECTORY_NODES[directory_node_ip],
            signed_message=their_certificate,
            my_id=their_id,
            allow_stale=True)

        # Verify the signed challenge uses the key in the certificate. todo: check challenge value
        DigitalSigning.verify(
            their_static_public_key=load_der_public_key(their_static_public_key),
            signed_message=signed_challenge,
            my_id=bytes.fromhex(open("./_keys/me/identifier.txt", "r").read()))

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
    def _handle_request_for_closer_nodes(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        Handle a request for closer nodes to a key. The data will be the key to find the closest nodes to.
        @param addr:
        @param connection_token:
        @param data:
        @return:
        """

        # Determine the key from the data, and get the closest nodes to the key.
        key = data
        closest_node = Address(ip=DHT.closest_node_to(key))
        logging.debug(f"\t\tClosest node to {key}: {closest_node.ip}")

        # Send the closest node (could be this node) to the requesting node.
        self._send_message_onwards(addr, connection_token, ControlConnectionProtocol.DHT_CLOSER_NODES_RES, pickle.dumps((key, closest_node)))

    @LogPre
    def _handle_response_for_closer_nodes(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """

        @param addr:
        @param connection_token:
        @param data:
        @return:
        """

        # Extract the key and IP from the data and save it to the dictionary.
        key, closest_node = pickle.loads(data)
        self._closer_nodes_to_files_resp[(connection_token, key)] = closest_node

    @LogPre
    def _handle_send_dht_broker_request(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        Send a DHT broker advertisement to a node of the client node's choosing. This broker node will be aware of a
        file existing on the network, and can talk to this node, to route requests back to the client node for the file
        information. The file information is encrypted differently per-node retrieving the file, so the broker node
        cannot store file contents.
        @param addr:
        @param connection_token:
        @param data:
        @return:
        """

        # Load the file name and broker node ip address from the data.
        file_name, broker_node_ip_address = pickle.loads(data)
        conversation_id = self._open_connection_to(broker_node_ip_address, token=connection_token)
        self._exit_node_broker_node_mapper[conversation_id.token] = ConnectionToken(token=connection_token, address=addr)

        # Send the advertisement to the broker node.
        self._send_message_onwards(
            addr=broker_node_ip_address,
            connection_token=conversation_id.token,
            command=ControlConnectionProtocol.DHT_ADV,
            data=file_name.encode())

    @LogPre
    def _handle_dht_advertisement(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        Handle a DHT advertisement from a broker node. This advertisement will be for a file that the broker node is
        aware of, and can route requests for the file to the client node.
        @param addr:
        @param connection_token:
        @param data:
        @return:
        """

        # Load the file name from the data, and save it to the dictionary.
        file_name = data.decode()
        self._broker_node_files[file_name] = connection_token
        logging.debug(f"\t\tAware of file: {file_name}")

    @LogPre
    def _handle_dht_get_file_from_broker(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        @param addr:
        @param connection_token:
        @param data:
        @return:
        """

        file_name, broker_node_ip = pickle.loads(data)
        stripped_file_name = file_name.rsplit(".")[0]

        # If this node is a broker node for the contents.
        if file_name in self._broker_node_files.keys():
            conversation_id = ConnectionToken(token=connection_token, address=addr)
            self._broker_node_file_requesters[str(random.randint(1000, 9999)) + file_name] = conversation_id

            exit_node_to_source_connection_token = [c for c in self._conversations if c.token == self._broker_node_files.get(file_name)]
            exit_node_to_source = exit_node_to_source_connection_token[0].address
            self._send_message_onwards(exit_node_to_source, self._broker_node_files.get(file_name), ControlConnectionProtocol.DHT_FILE_GET_FROM_SOURCE, data)

        # This is the exit node of the client route, so send the command to the broker node.
        else:
            new_connection_token = self._open_connection_to(broker_node_ip)
            self._exit_node_broker_node_mapper[new_connection_token.token] = ConnectionToken(token=connection_token, address=addr)
            self._send_message_onwards(broker_node_ip, new_connection_token.token, ControlConnectionProtocol.DHT_FILE_GET_FROM_BROKER, data)

    @LogPre
    def _handle_dht_get_file_from_source(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        @param addr:
        @param connection_token:
        @param data:
        @return:
        """

        file_name, broker_node_ip = pickle.loads(data)
        stripped_file_name = file_name.rsplit(".", 1)[0]
        logging.debug(f"\t\tGetting file: {file_name}")

        # This node is storing the file contents.
        if os.path.exists(f"./_files/stored/{stripped_file_name}"):
            file_contents = open(f"./_files/stored/{stripped_file_name}", "rb").read()
            self._tunnel_message_forwards(self._my_route.route[-1].connection_token.address, connection_token, ControlConnectionProtocol.DHT_FILE_CONTENTS_TO_BROKER, pickle.dumps((file_name, file_contents, broker_node_ip)))

        # This is the exit node of the host route, so send the command to the host through the route. todo: exit node map instead?
        else:
            # candidates = [c.address for c in self._conversations.keys() if c.token == connection_token and c.address != addr]
            # addr = candidates[0]
            old_connection_token = self._exit_node_broker_node_mapper[connection_token]
            addr, connection_token = old_connection_token.address, old_connection_token.token
            self._tunnel_message_backward(addr, connection_token, ControlConnectionProtocol.DHT_FILE_GET_FROM_SOURCE, data)
            del self._exit_node_broker_node_mapper[connection_token]

    @LogPre
    def _handle_dht_file_contents_to_broker(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        @param addr:
        @param connection_token:
        @param data:
        @return:
        """

        file_name, file_contents, broker_node_ip = pickle.loads(data)

        # If this node is a broker node for the contents.
        if file_name in self._broker_node_files.keys():
            requesters = [r for c, r in self._broker_node_file_requesters.items() if c[4:] == file_name]
            for requester in requesters:
                self._send_message_onwards(requester.address, requester.token, ControlConnectionProtocol.DHT_FILE_CONTENTS_TO_CLIENT, pickle.dumps((file_name, file_contents, broker_node_ip)))

        # Otherwise, this node is the exit node in the host route, so send the message to the broker node.
        else:
            new_connection_token = self._open_connection_to(broker_node_ip)
            # self._exit_node_broker_node_mapper[new_connection_token.token] = ConnectionToken(token=connection_token, address=addr)
            self._send_message_onwards(broker_node_ip, new_connection_token.token, ControlConnectionProtocol.DHT_FILE_CONTENTS_TO_BROKER, data)

    @LogPre
    def _handle_dht_file_contents_to_client(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        """
        @param addr:
        @param connection_token:
        @param data:
        @return:
        """

        # If this node is a client node requesting the contents.
        if self._my_route and self._my_route.connection_token.token == connection_token:
            file_name, file_contents, _ = pickle.loads(data)
            open(f"./_files/retrieved/{file_name}", "wb").write(file_contents)
            logging.debug(f"\t\tReceived file: {file_name}")

        # If this node is the exit node in the client's route, tunnel the message to the client node.
        else:
            # candidates = [c for c in self._conversations.keys() if c.token == connection_token and c.address != addr]
            # addr, connection_token = candidates[0].address, candidates[0].token
            old_connection_token = self._exit_node_broker_node_mapper[connection_token]
            addr, new_connection_token = old_connection_token.address, old_connection_token.token
            self._tunnel_message_backward(addr, new_connection_token, ControlConnectionProtocol.DHT_FILE_CONTENTS_TO_CLIENT, data)
            del self._exit_node_broker_node_mapper[connection_token]

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

        # Get the next command and data from the message, and send it to the target node. The "next_data" may still be
        # ciphertext if the intended target isn't the next node (could be the node after that), with multiple nested
        # messages of "CONN_FWD" commands.

        # Send the message to the target node. It will be automatically encrypted.
        self._send_message_onwards_raw(target_node, connection_token, data)

    # @LogPre
    # def _register_connection_as_secure(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
    #     logging.debug(f"Marking connection to {addr.ip} as secure")
    #
    #     conversation_id = ConnectionToken(token=connection_token, address=addr)
    #     self._conversations[conversation_id].secure = True

    @LogPre
    def _tunnel_message_forwards(self, addr: Address, connection_token: Bytes, command: ControlConnectionProtocol, data: Bytes) -> None:
        """

        @param addr: The target address where the command will be sent to (from curent exit node).
        @param connection_token:
        @param command: The command to send to the target address.
        @param data:
        @return:
        """
        # Encrypt per layer until the node in the route == the node that the data is being sent to.
        if self._my_route and self._my_route.connection_token.token == connection_token:
            route_node_addresses = [n.connection_token.address for n in self._my_route.route]
            target_node_route_index = route_node_addresses.index(addr) if addr in route_node_addresses else -1

            if target_node_route_index > -1:
                relay_nodes = list(reversed(self._my_route.route[1:target_node_route_index + 1]))
            else:
                relay_nodes = list(reversed(self._my_route.route[1:]))

            # Combine the data components (this data will be sent to "self" and forwarded on)
            data = command.value.to_bytes(1, "big") + connection_token + data

            # For each node in the path until the target node, apply a layer of encryption.
            for next_node in relay_nodes:
                # No shared secret when exchanging the KEM for the shared secret.
                if next_node.shared_secret:
                    data = SymmetricEncryption.encrypt(data, next_node.shared_secret.decapsulated_key)

                data = ControlConnectionProtocol.CONN_FWD.value.to_bytes(1, "big") + next_node.connection_token.token + data

            if relay_nodes:
                command, _, data = self._parse_message(data)
            else:
                command, data = ControlConnectionProtocol.CONN_FWD, data

        self._send_message_onwards(self._my_route.route[0].connection_token.address, connection_token, command, data)

    @LogPre
    def _tunnel_message_backward(self, addr: Address, connection_token: Bytes, command: ControlConnectionProtocol, data: Bytes) -> None:
        """

        @param addr: The previous address in the chain. The next node will use the connection token to chain again.
        @param connection_token:
        @param command:
        @param data:
        @return:
        """

        # Encrypt with 1 layer as this message is travelling backwards to the client node. Don't do this for sending
        # information to self.
        if not (self._my_route and self._my_route.connection_token.token == connection_token):
            data = command.value.to_bytes(1, "big") + connection_token + data
            if shared_secret := self._node_to_client_tunnel_keys[connection_token].shared_secret:
                client_key = shared_secret.decapsulated_key
                data = SymmetricEncryption.encrypt(data, client_key)

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
        data = command.value.to_bytes(1, "big") + connection_token + data
        self._send_message_onwards_raw(addr, connection_token, data)

    @LogPre
    def _send_message_onwards_raw(self, addr: Address, connection_token: Bytes, data: Bytes) -> None:
        # The only commands not encrypted are: CONN_REQ, CONN_ACC, CONN_REJ and CONN_SEC. The rest are encrypted.

        # Encrypt the connection to the direct neighbour node, if a shared secret has been established.
        conversation_id = ConnectionToken(token=connection_token, address=addr)

        if self._is_connected_to(addr, connection_token) and data[0] != ControlConnectionProtocol.CONN_ACC.value:
            while not self._conversations[conversation_id].secure:
                pass

            shared_secret = self._conversations[conversation_id].shared_secret
            data = SymmetricEncryption.encrypt(data, shared_secret)

        # if shared_secret := self._conversations[conversation_id].shared_secret:
        #     data = SymmetricEncryption.encrypt(data, shared_secret)

        # Send the data to the node (prepend the connection token because encryption will hide it).
        data = connection_token + data
        self._udp_server.udp_send(data, addr.socket_format())

    @LogPre
    def _recv_message(self, data: Bytes, raw_addr: Tuple[Str, Int]) -> None:
        logging.debug(f"\t\tReceived message from: {raw_addr[0]}")

        addr = Address(ip=raw_addr[0], port=raw_addr[1])
        connection_token, data = data[:32], data[32:]
        # logging.debug(f"\t\tConnection token: {connection_token}")
        # logging.debug(f"\t\tConnection tokens: {[c.token for c in self._conversations.keys()]}")
        # logging.debug(f"\t\tCheck: {connection_token in [c.token for c in self._conversations.keys()]}")

        # Decrypt the e2e connection if its encrypted (not encrypted when initiating a connection).
        # if connection_token in [c.token for c in self._conversations.keys()]:
        if ConnectionToken(token=connection_token, address=addr) in self._conversations.keys():
            # print("possibly decrypting e2e")
            conversation_id = ConnectionToken(token=connection_token, address=addr)

            if self._waiting_for_ack_from(addr, connection_token) and data[0] == ControlConnectionProtocol.CONN_ACC.value:
                pass
            elif addr.ip in DHT.DIRECTORY_NODES.keys() and data[0] == ControlConnectionProtocol.DIR_CER:
                pass

            else:
                # print("waiting for key to be set")
                while not self._conversations[conversation_id].secure:
                    pass

                # print("decrypting e2e")
                shared_secret = self._conversations[conversation_id].shared_secret
                data = SymmetricEncryption.decrypt(data, shared_secret)

            # if shared_secret := self._conversations[conversation_id].shared_secret:
            #     print("e2e decrypting")
            #     data = SymmetricEncryption.decrypt(data, shared_secret)

        # Decrypt any layered encryption (if the command is CONN_FWD).

        # Decrypt all layers (this node is the client node). The exception is when this node has send this node data, as
        # at this point, the idea is to just execute the command on this node.
        # todo : just call "self._handle_message directly(...)", and remove the "addr != Address.me()"?
        if not self._is_directory_node and self._my_route and self._my_route.connection_token.token == connection_token:
            if addr != Address.me():
                # print("decrypting all layers")
                relay_nodes = iter(self._my_route.route[1:])
                next_node = next(relay_nodes, None)

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
              and connection_token in self._node_to_client_tunnel_keys.keys()
              and self._node_to_client_tunnel_keys[connection_token].shared_secret):

            two_nodes_with_connection_token = [c.address for c in self._conversations.keys() if c.token == connection_token]
            from_previous_node = addr == two_nodes_with_connection_token[0]

            # Relay node receiving a message from the previous node in the route => decrypt a layer
            if from_previous_node:
                # print("unwrapping 1 layer")
                client_key = self._node_to_client_tunnel_keys[connection_token].shared_secret.decapsulated_key
                data = SymmetricEncryption.decrypt(data, client_key)

            # Relay node receiving a message from the next node in the route => add a layer of encryption
            elif self._parse_message(data)[0] == ControlConnectionProtocol.CONN_FWD:
                # print("wrapping 1 layer")
                client_key = self._node_to_client_tunnel_keys[connection_token].shared_secret.decapsulated_key
                data = SymmetricEncryption.encrypt(data, client_key)
                data = ControlConnectionProtocol.CONN_FWD.value.to_bytes(1, "big") + connection_token + data

                prev_node = two_nodes_with_connection_token[0]
                self._send_message_onwards_raw(prev_node, connection_token, data)
                return

        # Parse and handle the message
        command, connection_token, data = self._parse_message(data)
        logging.debug(f"\t\tParsed command: {command}")
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
