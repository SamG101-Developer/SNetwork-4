from dataclasses import dataclass
from enum import IntFlag

from crypto_engines.tools.secure_bytes import SecureBytes
from my_types import Bool, Optional


class ControlConnectionState(IntFlag):
    WAITING_FOR_ACK = 0x01
    CONNECTED       = 0x02
    SECURE          = 0x04


@dataclass(kw_only=True)
class ControlConnectionConversationInfo:
    state: ControlConnectionState
    their_static_public_key: SecureBytes
    shared_secret: Optional[SecureBytes]
    my_ephemeral_public_key: Optional[SecureBytes]
    my_ephemeral_secret_key: Optional[SecureBytes]
    secure: Bool


__all__ = ["ControlConnectionConversationInfo", "ControlConnectionState"]
