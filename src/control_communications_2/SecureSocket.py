from __future__ import annotations

import pickle
from socket import socket as Socket
from threading import Thread
from typing import Callable, Self

from crypto_engines.tools.secure_bytes import SecureBytes
from crypto_engines.crypto.symmetric_encryption import SymmetricEncryption
from control_communications_2.ConnectionDataPackage import ConnectionDataPackage


class SecureSocket:
    Handler = Callable[[Self, ConnectionDataPackage], None]

    _socket: Socket
    _e2e_key: SecureBytes
    _auto_handler: Handler
    _handling: bool

    def __init__(self, socket: Socket, e2e_key: SecureBytes, auto_handler: Handler = lambda *args: None):
        self._socket = socket
        self._e2e_key = e2e_key
        self._auto_handler = auto_handler
        self._handling = True

        thread = Thread(target=self._auto_handle)
        thread.start()

    def send(self, plain_text: ConnectionDataPackage) -> None:
        print(f"SENDING PLAINTEXT DATA: {plain_text}")
        data = SecureBytes(pickle.dumps(plain_text))
        data = SymmetricEncryption.encrypt(data, self._e2e_key)
        print(f"SENDING ENCRYPTED DATA: {data.raw}")
        self._socket.send(data.raw + b"\r\n")

    def recv(self) -> bytes:
        data = b""
        while not data.endswith(b"\r\n"):
            data += self._socket.recv(1024)
        data = SecureBytes(data[:-2])
        print(f"RECEIVED ENCRYPTED DATA: {data.raw}")
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
            data = self.recv()
            thread = Thread(target=self._auto_handler, args=(self, pickle.loads(data)))
            thread.start()
