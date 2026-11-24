"""Local client for Intelbras alarm panels.

ISECNet v1: AMT 1016 NET, AMT 2018 family, Smart models, AMT 4010 Smart (``AmtClient``).
ISECNet v2: AMT 8000 family and ANM 24 NET (``AmtV2Client``). ``open_panel`` picks one.
"""

from .client import (
    AmtClient,
    AmtError,
    AuthError,
    CommandError,
    PanelTimeout,
    WrongFamilyError,
    discover,
    discover_network,
    e9_request,
)
from .client_v2 import AmtV2Client, open_panel
from .decode import OpenZonesError, Status
from .decode_v2 import StatusV2
from .protocol_v2 import V2CommandError

__all__ = [
    "AmtClient",
    "AmtV2Client",
    "StatusV2",
    "V2CommandError",
    "WrongFamilyError",
    "open_panel",
    "AmtError",
    "AuthError",
    "CommandError",
    "OpenZonesError",
    "PanelTimeout",
    "Status",
    "discover",
    "discover_network",
    "e9_request",
]
__version__ = "0.3.0"
