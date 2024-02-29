from dataclasses import dataclass
from enum import IntFlag

from crypto_engines.tools.secure_bytes import SecureBytes
from my_types import Optional


class ControlConnectionState(IntFlag):
    WAITING_FOR_ACK = 0x00
    CONNECTED       = 0x01
    SECURE          = 0x02


@dataclass(kw_only=True)
class ControlConnectionConversationInfo:
    state: ControlConnectionState
    their_static_public_key: SecureBytes
    shared_secret: Optional[SecureBytes]
    my_ephemeral_public_key: Optional[SecureBytes]
    my_ephemeral_secret_key: Optional[SecureBytes]


__all__ = ["ControlConnectionConversationInfo", "ControlConnectionState"]
