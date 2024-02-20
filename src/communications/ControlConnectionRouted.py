from src.communications.ControlConnection import ControlConnectionB
from typing import List


class ControlConnectionRouted:
    _control_connection: ControlConnectionB
    _route: List[Node]

    def __init__(self, control_connection: ControlConnectionB) -> None:
        self._control_connection = control_connection
        self._route = []
