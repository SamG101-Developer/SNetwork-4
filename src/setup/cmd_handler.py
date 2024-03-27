import logging

from crypto_engines.crypto.hashing import Hashing
from crypto_engines.crypto.digital_signing import DigitalSigning
from control_communications_2.ConnectionHub import ConnectionHub, DirectoryHub
from my_types import Str, List

from argparse import Namespace
from threading import Thread
import os, socket


class CmdHandler:
    CONTROLLER: ConnectionHub = None
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
            my_identifier = Hashing.hash(my_static_key_pair.public_key)

            # Write the keys to disk
            my_static_key_pair.export("./_keys/me", "static")
            my_identifier.export("./_keys/me", "identifier")

    @staticmethod
    def _handle_join(_arguments: Namespace) -> None:
        if not all(os.path.exists(f"./_keys/me/{key}") for key in ["static.pk", "static.sk", "identifier.txt"]):
            logging.error(f"Static keys do not exist. Please generate them first.")
            return

        logging.debug(f"Joining network as a node.")
        # Setup the control connection server
        if not CmdHandler.CONTROLLER:
            CmdHandler.CONTROLLER = ConnectionHub()

    @staticmethod
    def _handle_route(arguments: Namespace) -> None:
        if not CmdHandler.CONTROLLER:
            CmdHandler.CONTROLLER = ConnectionHub()
        CmdHandler.CONTROLLER.create_route(arguments)

    @staticmethod
    def _handle_directory(arguments: Namespace) -> None:
        logging.debug(f"Joining network as a directory.")
        CmdHandler.CONTROLLER = DirectoryHub()
