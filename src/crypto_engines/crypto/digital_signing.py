from crypto_engines.crypto.hashing import Hashing
from crypto_engines.tools.secure_bytes import SecureBytes
from crypto_engines.tools.timestamp import Timestamp
from crypto_engines.keys.key_pair import KeyPair
from pqcrypto.sign import dilithium4 as Dilithium4


class SignedMessage:
    """
    Package a message against its signature, so that it can be sent to the recipient. Easier to handle a specific type
    rather than a tuple.
    """

    _raw_message: SecureBytes
    _signature: SecureBytes

    _message: SecureBytes
    _timestamp: SecureBytes
    _recipient_id: SecureBytes

    def __init__(self, raw_message: SecureBytes, signature: SecureBytes) -> None:
        # Assign the message and signature to the object.
        self._raw_message = raw_message
        self._signature = signature

        # Unmerge the message into its components.
        self._message, self._timestamp, self._recipient_id = raw_message.unmerge(3)

    @property
    def message(self) -> SecureBytes:
        # Return the message.
        return self._message

    @property
    def raw_message(self) -> SecureBytes:
        # Return the raw message.
        return self._raw_message

    @property
    def signature(self) -> SecureBytes:
        # Return the signature.
        return self._signature


class DigitalSigning:
    """
    Digital signing is used to sign messages, so that the recipient can verify that the message was sent by the sender.
    There are methods for signing, verifying and generating key pairs. The authentication isn't just private key signing
    oriented; it also uses timestamps and the recipient's ID to prevent replay attacks.
    """
    ALGORITHM = Dilithium4

    @staticmethod
    def generate_key_pair() -> KeyPair:
        # Generate a key pair and package it into a KeyPair object.
        public_key, secret_key = DigitalSigning.ALGORITHM.generate_keypair()
        return KeyPair(SecureBytes(secret_key), SecureBytes(public_key))

    @staticmethod
    def sign(my_static_private_key: SecureBytes, message: SecureBytes, their_id: SecureBytes) -> SignedMessage:
        # Get the current time and recipient id, and merge the information with the message.
        time_bytes = Timestamp.current_time_bytes()
        enriched_message = message.merge(time_bytes).merge(their_id)

        # Hash the message to keep the signature short, and sign it.
        hashed_message = Hashing.hash(enriched_message)
        signature = DigitalSigning.ALGORITHM.sign(my_static_private_key.raw, hashed_message.raw)

        # Package the message and signature into a SignedMessage object.
        return SignedMessage(enriched_message, SecureBytes(signature))

    @staticmethod
    def verify(their_static_public_key: SecureBytes, signed_message: SignedMessage, my_id: SecureBytes) -> bool:
        # Extract the message and reproduce the hash.
        enriched_message = signed_message.raw_message
        hashed_message = Hashing.hash(enriched_message)
        message, time_bytes, recipient_id = enriched_message.unmerge(3)

        tolerance = Timestamp.in_tolerance(Timestamp.current_time_bytes(), time_bytes)

        # Check that the id matches, that the timestamp is in tolerance and that the signature is valid.
        assert recipient_id == my_id, f"Recipient ID {str(recipient_id)[:20]}... != {str(my_id)[:20]}..."
        assert tolerance.in_tolerance, f"Timestamp {time_bytes} is out of tolerance by {tolerance.out_by}"
        assert DigitalSigning.ALGORITHM.verify(their_static_public_key.raw, hashed_message.raw, signed_message.signature.raw), "Signature is invalid"
        return True
