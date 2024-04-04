from dataclasses import dataclass
from enum import IntFlag

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

from src.MyTypes import Bool, Optional


class ControlConnectionState(IntFlag):
    WAITING_FOR_ACK = 0x01
    CONNECTED       = 0x02


@dataclass(kw_only=True)
class ControlConnectionConversationInfo:
    state: ControlConnectionState
    their_static_public_key: Optional[RSAPublicKey]
    shared_secret: Optional[bytes]
    my_ephemeral_public_key: Optional[RSAPublicKey]
    my_ephemeral_secret_key: Optional[RSAPrivateKey]
    secure: Bool


__all__ = ["ControlConnectionConversationInfo", "ControlConnectionState"]
