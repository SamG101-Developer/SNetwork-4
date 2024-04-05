from __future__ import annotations

import logging
from ipaddress import IPv4Address

from scapy.packet import Packet
from scapy.sendrecv import sniff, sendp
from scapy.layers.inet import IP, TCP, Ether

from src.MyTypes import Bytes, List, Str, Dict, Tuple
from src.control_communications.ControlConnectionRoute import Address
from src.crypto_engines.crypto.SymmetricEncryption import SymmetricEncryption


PACKET_PORT = 12346
HTTPS_PORT = 443


class ClientPacketInterceptor:
    """
    Listens on port 443, captures traffic, triple-encrypts it, adds the connection IDs, and re-routes the packet to the
    entry node, port 12346. There will only be 1 active route owned by this node at any time.
    """

    _connection_token: Bytes
    _node_tunnel_keys: List[Bytes]
    _relay_node_addresses: List[Str]
    _my_ip_address: Str

    def __init__(self, connection_token: Bytes, node_tunnel_keys: List[Bytes], relay_node_addresses: List[Str]):
        # Set the attribute values
        self._connection_token = connection_token
        self._node_tunnel_keys = node_tunnel_keys
        self._relay_node_addresses = relay_node_addresses
        self._my_ip_address = Address.me().ip

        # Begin intercepting
        self._begin_interception()

    def _begin_interception(self) -> None:
        # Begin sniffing on the HTTPS port (outgoing).
        sniff(filter=f"tcp port {HTTPS_PORT}", prn=self._transform_packet)

    def _transform_packet(self, old_packet: Packet) -> None:
        # Only process outgoing packets on the HTTPS port.
        if not (IP in old_packet and TCP in old_packet and old_packet[IP].src == self._my_ip_address):
            return

        # Copy the old packet from the IP layer, and remove the payload.
        new_packet = old_packet[IP].copy()
        new_packet.remove_payload()
        old_payload = old_packet[TCP].payload

        # Encrypt the payload with the exit node key.
        embedded_ip_address = IPv4Address(old_packet[IP].dst).packed
        new_payload = SymmetricEncryption.encrypt(embedded_ip_address + old_payload, self._node_tunnel_keys[2])
        new_payload += self._connection_token

        # Encrypt the payload with the intermediary node key.
        embedded_ip_address = IPv4Address(self._relay_node_addresses[2]).packed
        new_payload = SymmetricEncryption.encrypt(embedded_ip_address + new_payload, self._node_tunnel_keys[1])
        new_payload += self._connection_token

        # Encrypt the payload with the entry node key.
        embedded_ip_address = IPv4Address(self._relay_node_addresses[1]).packed
        new_payload = SymmetricEncryption.encrypt(embedded_ip_address + new_payload, self._node_tunnel_keys[0])
        new_payload += self._connection_token

        # Add the payload to the packet and route it to the entry node.
        new_packet.add_payload(new_payload)
        new_packet[TCP].dport = PACKET_PORT
        new_packet[IP].dst = self._relay_node_addresses[0]

        # Add the Ethernet layer and force checksums to be recalculated.
        new_packet = Ether() / new_packet
        del new_packet[TCP].chksum
        del new_packet[IP].chksum

        # Send the packet (to the entry node).
        sendp(new_packet)

        # Debug
        logging.debug(f"\033[33mPacket to {old_packet[IP].dst} intercepted and sent to entry node {self._relay_node_addresses[0]}.\033[0m")


class IntermediaryNodeInterceptor:
    """
    Listens on port 12346, captures traffic. Removes a layer of encryption by corresponding the connection ID to a key.
    Re-routes the packet to the next or previous node in the route, depending on the sender of the packet.
    """
    
    _node_tunnel_keys: Dict[Bytes, Bytes]  # {Connection Token: Tunnel Key}
    _prev_addresses: Dict[Bytes, Str]           # {Connection Token: Previous Address}
    _exit_node_interceptor: ExitNodeInterceptor
    
    def __init__(self):
        # Initialize the dictionaries
        self._node_tunnel_keys = {}
        self._prev_addresses = {}
        self._exit_node_interceptor = ExitNodeInterceptor()

        # Begin intercepting
        self._begin_interception()
        
    def register_prev_node(self, connection_token: Bytes, key: Bytes, previous_address: Str) -> None:
        # Register the connection token, previous key, and previous address.
        self._node_tunnel_keys[connection_token] = key
        self._prev_addresses[connection_token] = previous_address
        
    def _begin_interception(self) -> None:
        # Begin sniffing on the packet port.
        sniff(filter=f"tcp port {PACKET_PORT}", prn=self._transform_packet)
        
    def _transform_packet(self, old_packet: Packet) -> None:
        # Get the connection token from the packet, and check if it is in the dictionary.
        connection_token = old_packet[TCP].payload[-32:]
        if connection_token not in self._node_tunnel_keys: return
        
        # Depending on the sender of the packet, forward it to the next or previous node.
        if old_packet[IP].src == self._prev_addresses[connection_token]:
            self._forward_next(old_packet, connection_token)
        else:
            self._forward_prev(old_packet, connection_token)
            
    def _forward_next(self, old_packet: Packet, connection_token: Bytes) -> None:
        # Copy the old packet from the IP layer, and remove the payload.
        new_packet = old_packet[IP].copy()
        new_packet.remove_payload()
        old_payload = old_packet[TCP].payload[:-32]
        
        # Decrypt the payload with the next key.
        new_payload = SymmetricEncryption.decrypt(old_payload, self._node_tunnel_keys[connection_token])
        next_address, new_payload = new_payload[:4], new_payload[4:]
        
        # Add the payload to the packet and route it to the next node (could be the internet).
        new_packet.add_payload(new_payload)
        new_packet[TCP].dport = PACKET_PORT if IPv4Address(next_address).is_private else HTTPS_PORT
        new_packet[IP].dst = next_address
        
        # Register information to the exit node interceptor if the packet is going to the internet.
        if not IPv4Address(next_address).is_private:
            self._exit_node_interceptor.register_information(port=old_packet[TCP].sport, connection_token=connection_token)
        else:
            logging.debug(f"\033[34mPacket from {old_packet[IP].src} intercepted and sent forwards to the internet {next_address}.\033[0m")
            # todo: send the packet (safe to test first)
            return
        
        # Add the Ethernet layer and force checksums to be recalculated.
        new_packet = Ether() / new_packet
        del new_packet[IP].chksum
        del new_packet[TCP].chksum
        
        # Send the packet (to the next node or the internet).
        sendp(new_packet)

        # Debug
        logging.debug(f"\033[33mPacket from {old_packet[IP].src} intercepted and sent forwards to next node {next_address}.\033[0m")
        
    def _forward_prev(self, old_packet: Packet, connection_token: Bytes) -> None:
        # Copy the old packet from the IP layer, and remove the payload.
        new_packet = old_packet[IP].copy()
        new_packet.remove_payload()
        old_payload = old_packet[TCP].payload[:-32]
        
        # Encrypt the payload with the previous key, and add the connection token.
        new_payload = SymmetricEncryption.encrypt(old_payload, self._node_tunnel_keys[connection_token])
        new_payload += connection_token
        prev_address = self._prev_addresses[connection_token]
        
        # Add the payload to the packet and route it to the previous node.
        new_packet.add_payload(new_payload)
        new_packet[TCP].dport = PACKET_PORT
        new_packet[IP].dst = prev_address
        
        # Add the Ethernet layer and force checksums to be recalculated.
        new_packet = Ether() / new_packet
        del new_packet[IP].chksum
        del new_packet[TCP].chksum
        
        # Send the packet (to the previous node).
        sendp(new_packet)

        # Debug
        logging.debug(f"\033[35mPacket from {old_packet[IP].src} intercepted and sent backwards to next node {prev_address}.\033[0m")


class ExitNodeInterceptor:
    """
    Listens on port 443, and captures traffic not from the internet, on port 443. It differentiates between normal
    traffic and routing traffic by maintaining a list of external src ports being used to send data from port 443.
    """
    
    _port_mapping: Dict[int, Bytes]  # {Port: Connection Token}
    
    def __init__(self) -> None:
        # Initialize the dictionary
        self._port_mapping = {}

        # Begin intercepting
        self._begin_interception()
        
    def register_information(self, port: int, connection_token: Bytes) -> None:
        # Register the connection token to the port.
        self._port_mapping[port] = connection_token
        
    def _begin_interception(self) -> None:
        # Begin sniffing on the HTTPS port (incoming).
        sniff(filter=f"tcp port {HTTPS_PORT}", prn=self._transform_packet)
        
    def _transform_packet(self, old_packet: Packet) -> None:
        # Only process incoming packets on the HTTPS port.
        if not (IP in old_packet and TCP in old_packet and old_packet[TCP].dport == HTTPS_PORT):
            return
        
        # Otherwise, send the packet to itself on port 12346, and let the intermediary node handle it.
        new_packet = old_packet.copy()
        new_packet[TCP].dport = PACKET_PORT
        new_packet[IP].dst = Address.me().ip
        
        # Add the connection token to the packet.
        connection_token = self._port_mapping.get(old_packet[TCP].sport)
        old_payload = old_packet[TCP].payload
        new_packet[TCP].remove_payload()
        new_packet.add_payload(old_payload + connection_token)
        
        # Add the Ethernet layer and force checksums to be recalculated.
        new_packet = Ether() / new_packet
        del new_packet[IP].chksum
        del new_packet[TCP].chksum
        
        # Send the packet (to itself).
        sendp(new_packet)

        # Debug
        logging.debug(f"\033[36mPacket from {old_packet[IP].src} (internet) intercepted and sent to itself on port 12346.\033[0m")


__all__ = ["ClientPacketInterceptor", "IntermediaryNodeInterceptor"]