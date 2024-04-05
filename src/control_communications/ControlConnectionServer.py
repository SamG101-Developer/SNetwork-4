import socket
from threading import Thread

from src.MyTypes import Optional, Callable, Tuple, Int, Str


BUFFER_SIZE = 16384
CLIENT_PORT = 12345


class ControlConnectionServer:
    _socket: Optional[socket.socket] = None
    _temp_threads: list[Thread] = []
    on_message_received: Optional[Callable] = None

    def __init__(self) -> None:
        # Setup the socket of the control connection manager
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._server_socket_thread = Thread(target=self._setup_socket)
        self._server_socket_thread.start()
        self.on_message_received = None

    def _setup_socket(self) -> None:
        # Bind the UDP socket for incoming commands to this node
        self._socket.bind(("", CLIENT_PORT))

        # For each message received, handle it in a new thread
        while True:
            message = self._socket.recvfrom(BUFFER_SIZE)
            thread = Thread(target=self.on_message_received, args=(*message,))
            thread.start()
            self._temp_threads.append(thread)

    def udp_send(self, message: bytes, address: Tuple[Str, Int]) -> None:
        # Send a message to the specified address
        self._socket.sendto(message, address)


__all__ = ["ControlConnectionServer"]
