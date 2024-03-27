import dataclasses
from ipaddress import IPv4Address

from src.crypto_engines.crypto.digital_signing import SignedMessage
from src.crypto_engines.tools.secure_bytes import SecureBytes


@dataclasses.dataclass
class Certificate:
    authority: IPv4Address
    identifier: SecureBytes
    public_key: SecureBytes
    signature: SignedMessage
