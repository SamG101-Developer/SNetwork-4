from __future__ import annotations

import json
from socket import socket as Socket
from threading import Thread
from typing import Callable

from crypto_engines.tools.secure_bytes import SecureBytes
from crypto_engines.crypto.symmetric_encryption import SymmetricEncryption
from control_communications_2.ConnectionDataPackage import ConnectionDataPackage


class SecureSocket:
    Handler = Callable[[SecureSocket, ConnectionDataPackage], None]

    _socket: Socket
    _e2e_key: SecureBytes
    _auto_handler: Handler
    _handling: bool

    def __init__(self, socket: Socket, e2e_key: SecureBytes, auto_handler: Handler = lambda *args: None):
        self._socket = socket
        self._e2e_key = e2e_key
        self._auto_handler = auto_handler
        self._handling = False

        thread = Thread(target=self._auto_handle)
        thread.start()

    def send(self, plain_text: ConnectionDataPackage) -> None:
        data = SecureBytes(plain_text.to_bytes())
        data = SymmetricEncryption.encrypt(data, self._e2e_key)
        self._socket.send(data.raw)

    def recv(self, buffer_size: int) -> bytes:
        data = SecureBytes(self._socket.recv(buffer_size))
        data = SymmetricEncryption.decrypt(data, self._e2e_key)
        return data.raw

    def pause_handler(self):
        self._handling = False

    def resume_handler(self):
        self._handling = True

    def _auto_handle(self):
        while True:
            while not self._handling:
                pass
            data = self.recv(1024)
            thread = Thread(target=self._auto_handler, args=(self, json.loads(data.decode())))
            thread.start()
