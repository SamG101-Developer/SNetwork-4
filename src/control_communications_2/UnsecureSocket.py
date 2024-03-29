import pickle
from socket import socket as Socket

from control_communications_2.ConnectionDataPackage import ConnectionDataPackage


class UnsecureSocket:
    _socket: Socket

    def __init__(self, socket: Socket):
        self._socket = socket

    def send(self, plain_text: ConnectionDataPackage) -> None:
        data = pickle.dumps(plain_text)
        data += b"\r\n"
        self._socket.send(data)

    def recv(self) -> bytes:
        data = b""
        while not data.endswith(b"\r\n"):
            data += self._socket.recv(1024)
        return data[:-2]

    def getpeername(self):
        return self._socket.getpeername()
