from __future__ import annotations

from ipaddress import IPv4Address
from socket import socket as Socket
from threading import Thread
from typing import Callable

from control_communications_2.UnsecureSocket import UnsecureSocket


class ConnectionServer:
    Handler = Callable[[UnsecureSocket, IPv4Address], None]

    _handle_client: ConnectionServer.Handler
    _socket: Socket
    _server_thread: Thread

    def __init__(self, port: int, handle_client: ConnectionServer.Handler):
        # Setup the connection server attributes.
        self._handle_client = handle_client
        self._socket = Socket()
        self._server_thread = Thread(target=self._setup_socket)
        self._server_thread.start()

    def _setup_socket(self):
        # Bind the tcp socket and allow for 5 connections.
        self._socket.bind(("", 12345))
        self._socket.listen(5)

        # Accept connections and handle them through the handler function.
        while True:
            client_socket, address = self._socket.accept()
            client_socket = UnsecureSocket(client_socket)
            handle_thread = Thread(target=self._handle_client, args=(client_socket, IPv4Address(address[0])))
            handle_thread.start()
