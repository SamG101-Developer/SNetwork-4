from src.communications.ControlConnection import ControlConnectionB
from typing import Optional


class ControlConnectionManager:
    b_conn: Optional[ControlConnectionB]
    f_conn: Optional[ControlConnectionB]
