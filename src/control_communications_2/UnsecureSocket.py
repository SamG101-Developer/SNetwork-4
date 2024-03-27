import pickle
from socket import socket as Socket


class UnsecureSocket:
    _socket: Socket

    def __init__(self, socket: Socket):
        self._socket = socket

    def send(self, plain_text: ConnectionDataPackage) -> None:
        data = pickle.dumps(plain_text)
        data += "\r\n"
        self._socket.send(data)

    def recv(self) -> bytes:
        data = b""
        while not data.endswith(b"\r\n"):
            data += self._socket.recv(1024)
        return data

    def getpeername(self):
        return self._socket.getpeername()
