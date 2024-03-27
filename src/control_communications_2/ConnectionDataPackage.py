import dataclasses, json

from control_communications_2.ConnectionProtocol import ConnectionProtocol
from crypto_engines.tools.secure_bytes import SecureBytes


@dataclasses.dataclass(kw_only=True)
class ConnectionDataPackage:
    # A connection data package contains a command and data
    command: ConnectionProtocol
    data: SecureBytes

    def to_bytes(self) -> bytes:
        # Convert the data package to bytes.
        return json.dumps(dataclasses.asdict(self)).encode()
