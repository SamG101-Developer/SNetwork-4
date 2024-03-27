import dataclasses
from typing import Any

from control_communications_2.ConnectionProtocol import ConnectionProtocol


@dataclasses.dataclass(kw_only=True)
class ConnectionDataPackage:
    # A connection data package contains a command and data
    command: ConnectionProtocol
    data: Any
