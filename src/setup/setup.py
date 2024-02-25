from src.crypto_engines.crypto.digital_signing import DigitalSigning
from src.crypto_engines.crypto.hashing import Hashing
import os


def setup():
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
