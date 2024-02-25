from src.crypto_engines.crypto.digital_signing import DigitalSigning
from src.crypto_engines.crypto.hashing import Hashing
from src.my_types import Str, Dict

from src.control_communications.ControlConnectionManager import ControlConnectionManager

from argparse import Namespace
import os


class CmdHandler:
    CONTROLLER: ControlConnectionManager = ControlConnectionManager()

    def __init__(self, command: Str, arguments: Namespace) -> None:
        getattr(CmdHandler, f"_handle_{command}")(arguments)

    @staticmethod
    def _handle_keygen(_arguments: Namespace) -> None:
        # Check if the static keys already exist
        if not os.path.exists("./_keys/me"):
            # Create the directory for the keys
            os.makedirs("./_keys/me")

            # Generate the static key pair for digital signing, and the hash of the public key (identifier)
            my_static_key_pair = DigitalSigning.generate_key_pair()
            my_identifier = Hashing.hash(my_static_key_pair.public_key)

            # Write the keys to disk
            my_static_key_pair.export("./_keys/me", "static")
            my_identifier.export("./_keys/me", "identifier")

    @staticmethod
    def _handle_route(arguments: Namespace) -> None:
        CmdHandler.CONTROLLER.create_route(arguments)
