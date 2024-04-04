import json
from argparse import Namespace
from threading import Thread
import logging
import os
import sys

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.crypto_engines.crypto.Hashing import Hashing
from src.crypto_engines.crypto.DigitalSigning import DigitalSigning
from src.control_communications.ControlConnectionManager import ControlConnectionManager
from src.MyTypes import Str, List


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
    def _handle_reset(arguments: Namespace) -> None:
        logging.debug(f"Resetting the node (manual removal on directory node may be required).")

        if sys.platform == "win32":
            os.system("rmdir /s /q ./_keys")
            os.system("rmdir /s /q ./_cache")
            os.system("rmdir /s /q ./_certs")
        else:
            os.system("rm -rf ./_keys")
            os.system("rm -rf ./_cache")
            os.system("rm -rf ./_certs")

        # Remake empty directories.
        os.mkdir("./_keys")
        os.mkdir("./_certs")
        os.mkdir("./_cache")
        json.dump([], open("./_cache/dht_cache.json", "w"))

    @staticmethod
    def _handle_keygen(arguments: Namespace) -> None:
        # Check if the static keys already exist.
        if not os.path.exists("./_keys/me") or arguments.force:
            # Create the directory for the keys.
            os.makedirs("./_keys/me", exist_ok=True)

            # Generate the static key pair for digital signing, and the hash of the public key (identifier).
            my_static_key_pair = DigitalSigning.generate_key_pair()
            my_identifier = Hashing.hash(my_static_key_pair.public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hex()

            # Write the keys to disk.
            my_static_key_pair.export("./_keys/me", "static")
            open("./_keys/me/identifier.txt", "w").write(my_identifier)

    @staticmethod
    def _handle_join(_arguments: Namespace) -> None:
        if not all(os.path.exists(f"./_keys/me/{key}") for key in ["static_sec.pem", "static_pub.pem", "identifier.txt"]):
            logging.error(f"Static keys do not exist. Please generate them first.")
            return

        # Setup the control connection for a node.
        if not CmdHandler.CONTROLLER:
            logging.debug(f"Joining network as a node.")
            CmdHandler.CONTROLLER = ControlConnectionManager()
        else:
            logging.error(f"Already joined the network as a node.")

    @staticmethod
    def _handle_route(arguments: Namespace) -> None:
        if not CmdHandler.CONTROLLER:
            CmdHandler.CONTROLLER = ControlConnectionManager()
        CmdHandler.CONTROLLER.create_route(arguments)

    @staticmethod
    def _handle_directory(arguments: Namespace) -> None:
        if not all(os.path.exists(f"./_keys/me/{key}") for key in ["static_sec.pem", "static_pub.pem", "identifier.txt"]):
            logging.error(f"Static keys do not exist. Please generate them first.")
            return

        # Setup the control connection for a directory server.
        if not CmdHandler.CONTROLLER:
            logging.debug(f"Joining network as a directory.")
            CmdHandler.CONTROLLER = ControlConnectionManager(is_directory_node=True)
        else:
            logging.error(f"Already joined the network as a directory.")
