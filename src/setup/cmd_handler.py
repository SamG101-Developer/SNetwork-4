from crypto_engines.tools.secure_bytes import SecureBytes
from crypto_engines.crypto.digital_signing import DigitalSigning
from crypto_engines.crypto.hashing import Hashing
from control_communications.ControlConnectionManager import ControlConnectionManager
from control_communications.ControlConnectionServer import ControlConnectionServer
from my_types import Str, List

from argparse import Namespace
from threading import Thread
import os, socket


class CmdHandler:
    CONTROLLER: ControlConnectionManager = None
    THREADS: List[Thread] = []

    def __init__(self, command: Str, arguments: Namespace) -> None:
        thread = Thread(target=CmdHandler._handle, args=(command, arguments))
        thread.start()
        CmdHandler.THREADS.append(thread)

    @staticmethod
    def _handle(command: Str, arguments: Namespace) -> None:
        getattr(CmdHandler, f"_handle_{command}")(arguments)

    @staticmethod
    def _handle_keygen(arguments: Namespace) -> None:
        # Check if the static keys already exist
        if not os.path.exists("./_keys/me") or arguments.force:
            # Create the directory for the keys
            os.makedirs("./_keys/me", exist_ok=True)

            # Generate the static key pair for digital signing, and the hash of the public key (identifier)
            my_static_key_pair = DigitalSigning.generate_key_pair()
            my_identifier = SecureBytes(socket.gethostbyname(socket.gethostname()).encode())  # Hashing.hash(my_static_key_pair.public_key)

            # Write the keys to disk
            my_static_key_pair.export("./_keys/me", "static")
            my_identifier.export("./_keys/me", "identifier")

    @staticmethod
    def _handle_join(_arguments: Namespace) -> None:
        # Setup the control connection server
        if not CmdHandler.CONTROLLER:
            CmdHandler.CONTROLLER = ControlConnectionManager()

    @staticmethod
    def _handle_route(arguments: Namespace) -> None:
        if not CmdHandler.CONTROLLER:
            CmdHandler.CONTROLLER = ControlConnectionManager()
        CmdHandler.CONTROLLER.create_route(arguments)
