from dataclasses import dataclass
from enum import Enum

from crypto_engines.tools.secure_bytes import SecureBytes
from my_types import Optional


class ControlConnectionState(Enum):
    WAITING_FOR_ACK = 0
    CONNECTED = 1


@dataclass(kw_only=True)
class ControlConnectionConversationInfo:
    state: ControlConnectionState
    their_static_public_key: SecureBytes
    shared_secret: Optional[SecureBytes]
    my_ephemeral_public_key: Optional[SecureBytes]
    my_ephemeral_secret_key: Optional[SecureBytes]


__all__ = ["ControlConnectionConversationInfo", "ControlConnectionState"]
