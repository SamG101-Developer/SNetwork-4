from __future__ import annotations
import pickle

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from src.crypto_engines.crypto.Hashing import Hashing
from src.crypto_engines.tools.Timestamp import Timestamp
from src.crypto_engines.tools.KeyPair import KeyPair


class DigitalSigning:
    """
    Digital signing is used to sign messages, so that the recipient can verify that the message was sent by the sender.
    There are methods for signing, verifying and generating key pairs. The authentication isn't just private-key-signing
    oriented; it also uses timestamps, and the recipient's ID to prevent replay attacks.
    """

    SEC_PEM_SIZE = 1704
    PUB_PEM_SIZE = 451

    @staticmethod
    def generate_key_pair() -> KeyPair:
        # Generate a key pair and package it into a KeyPair object.
        secret_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = secret_key.public_key()
        return KeyPair(secret_key, public_key)

    @staticmethod
    def sign(my_static_private_key: RSAPrivateKey, message: bytes, their_id: bytes) -> SignedMessage:
        # Get the current time and recipient id, and merge the information with the message.
        time_bytes = Timestamp.current_time_bytes()
        enriched_message = pickle.dumps((message, time_bytes, their_id))

        # Hash the message to keep the signature short, and sign it.
        hashed_message = Hashing.hash(enriched_message)
        signature = my_static_private_key.sign(
            data=hashed_message,
            padding=PSS(
                mgf=MGF1(algorithm=Hashing.ALGORITHM),
                salt_length=PSS.MAX_LENGTH
            ),
            algorithm=Hashing.ALGORITHM)

        # Package the message and signature into a SignedMessage object.
        return SignedMessage(enriched_message, bytes(signature))

    @staticmethod
    def verify(their_static_public_key: RSAPublicKey, signed_message: SignedMessage, my_id: bytes, allow_stale: bool = False) -> bool:
        # Extract the message and reproduce the hash.
        enriched_message = signed_message.raw_message
        hashed_message = Hashing.hash(enriched_message)
        message, time_bytes, recipient_id = pickle.loads(enriched_message)

        tolerance = Timestamp.in_tolerance(Timestamp.current_time_bytes(), time_bytes)

        # Check that the id matches, that the timestamp is in tolerance and that the signature is valid.
        assert recipient_id == my_id, f"Recipient ID {str(recipient_id)[:20]}... != {str(my_id)[:20]}..."

        their_static_public_key.verify(
            data=hashed_message,
            signature=signed_message.signature,
            padding=PSS(
                mgf=MGF1(algorithm=Hashing.ALGORITHM),
                salt_length=PSS.MAX_LENGTH
            ),
            algorithm=Hashing.ALGORITHM)

        return True


class SignedMessage:
    """
    Package a message against its signature, so that it can be sent to the recipient. Easier to handle a specific type
    rather than a tuple.
    """

    _raw_message: bytes
    _signature: bytes

    _message: bytes
    _timestamp: bytes
    _recipient_id: bytes

    def __init__(self, raw_message: bytes, signature: bytes) -> None:
        # Assign the message and signature to the object.
        self._raw_message = raw_message
        self._signature = signature

        # Unmerge the message into its components.
        self._message, self._timestamp, self._recipient_id = pickle.loads(raw_message)

    @property
    def message(self) -> bytes:
        # Return the message.
        return self._message

    @property
    def raw_message(self) -> bytes:
        # Return the raw message.
        return self._raw_message

    @property
    def signature(self) -> bytes:
        # Return the signature.
        return self._signature
