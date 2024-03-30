from __future__ import annotations

from scapy.sendrecv import sniff, sendp, Packet
from scapy.layers.inet import IP, TCP, Ether

import socket

from my_types import Dict, Bytes, List, Str, Tuple, Int
from crypto_engines.crypto.symmetric_encryption import SymmetricEncryption
from crypto_engines.tools.secure_bytes import SecureBytes


class ClientPacketInterceptor:
    """
    The ClientPacketInterceptor intercepts packets that are sent from the client node (owner of a route) to some web
    server. It applies layered encryption that each node will remove a layer of and forward on to the next node. Web
    traffic is sent from port 443.
    """

    _connection_token: Bytes
    _keys: List[SecureBytes]
    _addresses: List[Str]
    _my_ip: Str

    def __init__(self, connection_token: Bytes, keys: List[SecureBytes], addresses: List[Str]) -> None:
        self._connection_token = connection_token
        self._keys = keys
        self._addresses = addresses
        self._my_ip = socket.gethostbyname(socket.gethostname())
        self._begin_interception()

    def _begin_interception(self) -> None:
        sniff(filter="tcp port 443", prn=self._layer_packet)

    def _layer_packet(self, original_packet: Packet) -> None:
        if IP in original_packet and TCP in original_packet:
            if original_packet[IP].src == self._my_ip:
                # Copy the packet and remove the original payload.
                new_packet = original_packet[IP].copy()
                new_packet.remove_payload()
                node_port = 12346
                payload = bytes(original_packet[TCP].payload)

                # Encrypt the payload with the exit node key.
                payload = SymmetricEncryption.encrypt(SecureBytes(payload), self._keys[2]).raw
                payload += self._connection_token

                # Encrypt the payload with the intermediary node key.
                payload = SymmetricEncryption.encrypt(SecureBytes(payload), self._keys[1]).raw
                payload += self._connection_token

                # Encrypt the payload with the entry node key.
                payload = SymmetricEncryption.encrypt(SecureBytes(payload), self._keys[0]).raw
                payload += self._connection_token

                # Add the payload to the packet and route it to the entry node.
                new_packet.add_payload(payload)
                new_packet[IP].dst = self._addresses[0]
                new_packet[TCP].dport = node_port
                new_packet = Ether() / new_packet

                # Force checksums to be recalculated.
                del new_packet[IP].chksum
                del new_packet[TCP].chksum

                # Send the packet.
                sendp(new_packet)


class ExitNodePacketInterceptor:
    """
    The ExitNodePacketInterceptor intercepts traffic on port 443 too, and always runs even if this node isn't
    necessarily an exit node. This is because a node doesn't know its position in routes. Not all port 443 traffic is
    for routing, so check the destination port on the TCP layer, to see if it corresponds to a previously established
    connection.
    """

    _keys: Dict[Int, Tuple[SecureBytes, Str]]  # AES key and destination address

    def __init__(self) -> None:
        self._keys = {}
        self._begin_interception()

    def register_key(self, port: Int, address: Str, key: SecureBytes) -> None:
        # Register a custom NAT behaviour by associating a key and address pair with a port.
        self._keys[port] = (key, address)

    def _begin_interception(self) -> None:
        # Sniff packets on port 443.
        sniff(filter="tcp port 443", prn=self._layer_packet_backwards)

    def _layer_packet_backwards(self, original_packet: Packet) -> None:
        if IP in original_packet and TCP in original_packet:
            if original_packet[IP].dst == socket.gethostbyname(socket.gethostname()):
                # Copy the packet and remove the original payload.
                new_packet = original_packet[IP].copy()
                new_packet.remove_payload()
                node_port = 12346
                payload = bytes(original_packet[TCP].payload)

                # Check if this packet is meant for routing
                if original_packet[TCP].dport not in self._keys:
                    return

                # Add the connection token and encrypt the payload with the AES key.
                payload = SymmetricEncryption.encrypt(SecureBytes(payload), self._keys[original_packet[TCP].dport][0]).raw
                payload += self._keys[original_packet[TCP].dport][0]

                # Add the payload to the packet and route it to the previous node.
                new_packet.add_payload(payload)
                new_packet[IP].dst = self._keys[original_packet[TCP].dport][1]
                new_packet[TCP].dport = node_port
                new_packet = Ether() / new_packet

                # Force checksums to be recalculated.
                del new_packet[IP].chksum
                del new_packet[TCP].chksum

                # Send the packet.
                sendp(new_packet)


class IntermediaryNodePacketForwarder:
    """
    The IntermediaryNodePacketForwarder is responsible for forwarding packets it receives on port 12346. This could be
    either moving forwards or backwards in the route. Either way, for a connection token, if the src address is a
    forward address, then decrypt a layer, and send the packet to the next node. If the src address is a backward
    address, then encrypt a layer and send the packet to the previous node.
    """

    _keys: Dict[Bytes, Tuple[SecureBytes, SecureBytes]]  # {Connection token: Forward & Backward keys}
    _addresses: Dict[Bytes, Tuple[Str, Str]]  # {Forward & Backward addresses}
    _exit_node_interceptor: ExitNodePacketInterceptor

    def __init__(self, exit_node_interceptor: ExitNodePacketInterceptor) -> None:
        self._keys = {}
        self._addresses = {}
        self._exit_node_interceptor = exit_node_interceptor
        self._begin_interception()

    def _begin_interception(self) -> None:
        sniff(filter="tcp port 12346", prn=self._layer_packet)

    def register_keys_and_addresses(
            self, connection_token: Bytes, forward_key: SecureBytes, backward_key: SecureBytes,
            forward_address: Str, backward_address: Str) -> None:
        # Register an address pair and the keys needed for them against a connection token.
        self._keys[connection_token] = (forward_key, backward_key)
        self._addresses[connection_token] = (forward_address, backward_address)

    def _layer_packet(self, original_packet: Packet) -> None:
        if IP in original_packet and TCP in original_packet:
            # Get who the packet is from (the source address).
            who_from = original_packet[IP].src

            # Match against known addresses and determine if the address is known, and if it is a previous or next node
            # in a route.
            for forward_address, backward_address in self._addresses.values():
                if who_from == backward_address:
                    self._forward_packet(original_packet, forward_address)
                elif who_from == forward_address:
                    self._backward_packet(original_packet, backward_address)

    def _forward_packet(self, original_packet: Packet, forward_address: Str) -> None:
        # Notify the exit node interceptor of the connection token and key.
        source_port = original_packet[TCP].sport
        self._exit_node_interceptor.register_key(
            port=original_packet[TCP].sport,
            address=forward_address,
            key=self._keys[original_packet[TCP].payload[-32:]][0])

        # Copy the packet and remove the original payload.
        new_packet = original_packet[IP].copy()
        new_packet.remove_payload()
        payload = bytes(original_packet[TCP].payload)

        # Decrypt the payload with the forward key.
        connection_token, payload = payload[-32:], payload[:-32]
        payload = SymmetricEncryption.decrypt(SecureBytes(payload), self._keys[connection_token][0]).raw

        # Add the payload to the packet and route it to the next node.
        new_packet.add_payload(payload)
        new_packet[IP].dst = forward_address
        new_packet[TCP].dport = 12346
        new_packet = Ether() / new_packet

        # Force checksums to be recalculated.
        del new_packet[IP].chksum
        del new_packet[TCP].chksum

        # Send the packet.
        sendp(new_packet)

    def _backward_packet(self, original_packet: Packet, backward_address: Str) -> None:
        # Copy the packet and remove the original payload.
        new_packet = original_packet[IP].copy()
        new_packet.remove_payload()
        payload = bytes(original_packet[TCP].payload)

        # Encrypt the payload with the backward key.
        connection_token, payload = payload[-32:], payload[:-32]
        payload = SymmetricEncryption.encrypt(SecureBytes(payload), self._keys[connection_token][1]).raw

        # Add the payload to the packet and route it to the previous node.
        new_packet.add_payload(payload)
        new_packet[IP].dst = backward_address
        new_packet[TCP].dport = 12346
        new_packet = Ether() / new_packet

        # Force checksums to be recalculated.
        del new_packet[IP].chksum
        del new_packet[TCP].chksum

        # Send the packet.
        sendp(new_packet)
