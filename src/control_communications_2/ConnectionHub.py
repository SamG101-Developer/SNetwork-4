from __future__ import annotations

import json, os
import logging
import pickle
import socket
from typing import Any, Dict, List, Tuple
from ipaddress import IPv4Address
from socket import socket as Socket

from control_communications_2.UnsecureSocket import UnsecureSocket
from crypto_engines.crypto.hashing import Hashing
from crypto_engines.crypto.digital_signing import DigitalSigning, SignedMessage
from crypto_engines.crypto.key_encapsulation import KEM
from crypto_engines.keys.key_pair import KeyPair
from crypto_engines.tools.secure_bytes import SecureBytes
from crypto_engines.tools.certificate import Certificate, CertificateData
from distributed_hash_table.DHT import DHT

from control_communications_2.ConnectionDataPackage import ConnectionDataPackage
from control_communications_2.ConnectionProtocol import ConnectionProtocol
from control_communications_2.ConnectionServer import ConnectionServer
from control_communications_2.SecureSocket import SecureSocket


class ConnectionRoute:
    ...


class ConnectionHub:
    _tcp_server: ConnectionServer
    _connections: List[SecureSocket]
    _node_to_client_tunnel_keys: Dict[Socket, SecureBytes]

    def __init__(self):
        # Setup the connection server for incoming connections.
        self._tcp_server = ConnectionServer(12345, self._handle_client)
        self._connections = []
        self._node_to_client_tunnel_keys = {}

        # Get a certificate if this is a new node on the network.
        if not os.path.exists("./_certs/certificate.ctf"):
            self._obtain_certificate_from_directory_node()

        # Get some node IP addresses from the directory node if the cache is empty.
        if len(json.loads(open("./_cache/dht_cache.json").read())) == 0:
            self._bootstrap_from_directory_node()

        # Refresh the IP list by exchanging with neighbours.
        self._refresh_cache()

    def _handle_client(self, client_socket: UnsecureSocket, address: IPv4Address) -> None:
        secure_connection = _HandleNewClient(client_socket, address, self._handle_command)
        self._connections.append(secure_connection)

    def _handle_command(self, socket: SecureSocket, data: ConnectionDataPackage) -> None:
        print(f"Unknown command: {data.command}.")

    def _obtain_certificate_from_directory_node(self):
        # Create a static asymmetric key pair and export it.
        static_asymmetric_key_pair = KeyPair().import_(f"./_keys/me", "static")
        request = ConnectionDataPackage(command=ConnectionProtocol.DIR_CER_REQ, data=static_asymmetric_key_pair.public_key.raw)

        # Send the request to the directory node for a certificate.
        logging.debug("Requesting a certificate from a directory node...")
        conn = CreateUnsecureConnection(DHT.get_random_directory_node())
        conn.send(request)

        # Receive the certificate and save it. todo: verify
        response = conn.recv()
        response = _VerifyResponseIntegrity(response, ConnectionProtocol.DIR_CER_RES)
        logging.debug("Received a certificate from a directory node.")

        SecureBytes(_DumpData(response.data)).export("./_certs", "certificate", ".ctf")

    def _bootstrap_from_directory_node(self):
        # Create a request for bootstrap nodes.
        logging.debug("Requesting bootstrap nodes from a directory node...")
        conn = CreateSecureConnection(DHT.get_random_directory_node())
        request = ConnectionDataPackage(command=ConnectionProtocol.DIR_LST_REQ, data=b"")

        # Send it to the directory node.
        conn.pause_handler()
        conn.send(request)
        logging.debug("Sent a request for bootstrap nodes to a directory node.")

        # Receive the IP addresses of the bootstrap nodes.
        response = conn.recv()
        response = _VerifyResponseIntegrity(response, ConnectionProtocol.DIR_LST_RES)
        logging.debug("Received bootstrap nodes from a directory node.")
        conn.resume_handler()

        bootstrap_nodes: List[Tuple[IPv4Address, SecureBytes]] = response.data

        # Cache the bootstrap nodes in the DHT cache.
        for ip_address, public_key in bootstrap_nodes:
            DHT.cache_node_information(
                node_id=Hashing.hash(public_key).raw,
                ip_address=ip_address.compressed,
                node_public_key=public_key.raw)

    def _refresh_cache(self):
        ...


def CreateUnsecureConnection(address: str) -> UnsecureSocket:
    # Create a raw connection to the address.
    underlying_socket = socket.create_connection((address, 12345))
    return UnsecureSocket(underlying_socket)


def CreateSecureConnection(address: str) -> SecureSocket:
    # Generate an ephemeral key pair, and sign the public key with the static secret key.
    my_static_secret_key = KeyPair().import_("./_keys/me", "static").secret_key
    my_ephemeral_secret_key, my_ephemeral_public_key = KEM.generate_key_pair().both()
    my_ephemeral_public_key_signed = DigitalSigning.sign(
        my_static_private_key=my_static_secret_key,
        message=my_ephemeral_public_key,
        their_id=DHT.get_id(address))

    # Create the socket and send the connection request.
    conn = CreateUnsecureConnection(address)
    request = ConnectionDataPackage(command=ConnectionProtocol.CON_CON_REQ, data=my_ephemeral_public_key_signed)
    conn.send(request)

    # Receive either a CON_CON_[ACC|REJ], or a DHT_CER_REQ.
    response = conn.recv()
    response = _VerifyResponseIntegrity(response, ConnectionProtocol.CON_CON_ACC, ConnectionProtocol.CON_CON_REJ, ConnectionProtocol.DHT_CER_REQ)

    # Send the certificate to prove identity.
    if response.command == ConnectionProtocol.DHT_CER_REQ:
        my_certificate = SecureBytes().import_(f"./_certs", "certificate", ".ctf")
        conn.send(ConnectionDataPackage(command=ConnectionProtocol.DHT_CER_RES, data=my_certificate))

        # The next response will be a CON_CON_[ACC|REJ].
        response = conn.recv()
        response = _VerifyResponseIntegrity(response, ConnectionProtocol.CON_CON_ACC, ConnectionProtocol.CON_CON_REJ)

    if response.command == ConnectionProtocol.CON_CON_REJ:
        raise Exception("Connection rejected.")

    # Verify the signed encapsulated shared secret.
    kem_wrapped_shared_secret_signed = response.data
    DigitalSigning.verify(
        signed_message=kem_wrapped_shared_secret_signed,
        their_static_public_key=DHT.get_static_public_key(address),
        my_id=SecureBytes().import_("./_keys/me", "identifier", ".txt"))

    shared_secret = KEM.kem_unwrap(
        my_ephemeral_secret_key=my_ephemeral_secret_key,
        encapsulated_key=kem_wrapped_shared_secret_signed.message).decapsulated_key

    logging.debug(f"Encrypted connection established to {address} {shared_secret}.")

    # Create a secure connection with the key.
    return SecureSocket(conn._socket, shared_secret)


def _HandleNewClient(client_socket: UnsecureSocket, address: IPv4Address, auto_handler: SecureSocket.Handler, request=None) -> SecureSocket:
    # Receive the connection request and verify the integrity.
    request = request or client_socket.recv()
    request = _VerifyResponseIntegrity(request, ConnectionProtocol.CON_CON_REQ)

    # Check if this node is known (is it in the DHT cache?)
    if DHT.get_static_public_key(address.compressed, silent=True) is None:
        # Request a certificate from the DHT node.
        client_socket.send(ConnectionDataPackage(command=ConnectionProtocol.DHT_CER_REQ, data=b""))

        # Get the certificate from the node.
        response = client_socket.recv()
        response = _VerifyResponseIntegrity(response, ConnectionProtocol.DHT_CER_RES)

        # Verify the certificate and cache the node information in the DHT.
        certificate: Certificate = response.data
        authority = _LoadData(certificate.signature.message.raw).authority
        DigitalSigning.verify(
            signed_message=certificate.signature,
            their_static_public_key=DHT.DIRECTORY_NODES[authority],
            my_id=Hashing.hash(certificate.signature.message))

        DHT.cache_node_information(
            node_id=Hashing.hash(certificate.signature.message).raw,
            ip_address=address.compressed,
            node_public_key=certificate.signature.message.raw)

    # Verify their signed ephemeral public key.
    their_ephemeral_public_key_signed: SignedMessage = request.data
    DigitalSigning.verify(
        signed_message=their_ephemeral_public_key_signed,
        their_static_public_key=DHT.get_static_public_key(address.compressed),
        my_id=SecureBytes().import_("./_keys/me", "identifier", ".txt"))

    # Create the symmetric shared secret, wrap in with a KEM, and sign it.
    their_ephemeral_public_key = their_ephemeral_public_key_signed.message
    kem_wrapped_shared_secret  = KEM.kem_wrap(their_ephemeral_public_key)
    kem_wrapped_shared_secret_signed = DigitalSigning.sign(
        my_static_private_key=KeyPair().import_("./_keys/me", "static").secret_key,
        message=kem_wrapped_shared_secret.encapsulated_key,
        their_id=DHT.get_id(address.compressed))

    # Send the signed shared secret to the client.
    client_socket.send(ConnectionDataPackage(command=ConnectionProtocol.CON_CON_ACC, data=kem_wrapped_shared_secret_signed))

    # Create a secure connection with the key.
    shared_secret = kem_wrapped_shared_secret.decapsulated_key
    secure_connection = SecureSocket(client_socket._socket, shared_secret, auto_handler)
    logging.debug(f"Encrypted connection established to {address}: {shared_secret}.")
    return secure_connection


def _DirectoryNodeHandlesNewClient(client_socket: UnsecureSocket, address: IPv4Address, auto_handler: SecureSocket.Handler) -> SecureSocket:
    request = client_socket.recv()
    request = _VerifyResponseIntegrity(request, ConnectionProtocol.CON_CON_REQ, ConnectionProtocol.DIR_CER_REQ)

    if request.command == ConnectionProtocol.DIR_CER_REQ:
        logging.debug(f"Generating certificate for {address}")

        # Determine the requesting node's static public key and id.
        their_static_public_key = SecureBytes(request.data)
        their_id = Hashing.hash(their_static_public_key)

        # Create a certificate for the node.
        my_ip = IPv4Address(client_socket.getpeername()[0])
        certificate = Certificate(
            signature=DigitalSigning.sign(
                my_static_private_key=KeyPair().import_("./_keys/me", "static").secret_key,
                message=SecureBytes(_DumpData(CertificateData(
                    authority=my_ip,
                    identifier=their_id,
                    public_key=their_static_public_key))),
                their_id=their_id))

        # Send the certificate to the node.
        client_socket.send(ConnectionDataPackage(command=ConnectionProtocol.DIR_CER_RES, data=certificate))

        # Cache the certificate in the directory node.
        DHT.cache_node_information(
            node_id=their_id.raw,
            ip_address=my_ip.compressed,
            node_public_key=their_static_public_key.raw)

    else:
        pre_request = _DumpData(request)
        return _HandleNewClient(client_socket, address, auto_handler, request=pre_request)


def _VerifyResponseIntegrity(response: bytes, *expected_commands: ConnectionProtocol) -> ConnectionDataPackage:
    response: ConnectionDataPackage = pickle.loads(response)
    if response.command not in expected_commands:
        raise Exception(f"Invalid command in response. Got {response.command}, expected 1 from {[*expected_commands]}")
    return response


def _DumpData(obj: object) -> bytes:
    pickled = pickle.dumps(obj)
    return pickled


def _LoadData(data: bytes) -> Any:
    obj = pickle.loads(data)
    return obj


class DirectoryHub:
    _tcp_server: ConnectionServer
    _connections: List[SecureSocket]

    def __init__(self):
        self._tcp_server = ConnectionServer(12345, self._handle_new_client)
        self._connections = []

    def _handle_new_client(self, client_socket: UnsecureSocket, address: IPv4Address) -> None:
        secure_connection = _DirectoryNodeHandlesNewClient(client_socket, address, self._handle_command)
        self._connections.append(secure_connection)

    def _handle_list_request(self, client: SecureSocket, data: ConnectionDataPackage):
        logging.debug(f"Received a list request from {client._socket.getpeername()[0]}.")

        # Get a list of random nodes from the DHT cache.
        random_nodes = [client._socket.getpeername()[0]]
        number_of_nodes_to_send_back = min(3, DHT.total_nodes_known(block_list=random_nodes))
        for i in range(number_of_nodes_to_send_back):
            random_node = DHT.get_random_node(block_list=random_nodes)
            random_nodes.append(random_node["ip"])

        # Send the list of nodes to the requesting node.
        response = ConnectionDataPackage(command=ConnectionProtocol.DIR_LST_RES, data=random_nodes)
        client.send(response)

    def _handle_command(self, socket: SecureSocket, data: ConnectionDataPackage) -> None:
        match data.command:
            case ConnectionProtocol.DIR_LST_REQ:
                self._handle_list_request(socket, data)
            case _:
                print(f"Unknown command: {data.command}.")
