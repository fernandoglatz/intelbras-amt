"""Local client for Intelbras AMT ISECNet v1 alarm panels (AMT 1016 NET, 2018 family, Smart, 4010)."""

from .client import (
    AmtClient,
    AmtError,
    AuthError,
    CommandError,
    PanelTimeout,
    discover,
    discover_network,
    e9_request,
)
from .decode import OpenZonesError, Status

__all__ = [
    "AmtClient",
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
__version__ = "0.2.0"
