import dataclasses
from ipaddress import IPv4Address

from crypto_engines.crypto.digital_signing import SignedMessage
from crypto_engines.tools.secure_bytes import SecureBytes


@dataclasses.dataclass
class Certificate:
    signature: SignedMessage


@dataclasses.dataclass
class CertificateData:
    authority: IPv4Address
    identifier: SecureBytes
    public_key: SecureBytes
