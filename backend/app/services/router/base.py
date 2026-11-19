from abc import ABC, abstractmethod
import logging
from typing import Any

logger = logging.getLogger(__name__)


class BaseRouterDriver(ABC):
    """Abstract base class for all consumer and enterprise router drivers."""

    def __init__(self, config: Any | None = None):
        self.config = config

    @abstractmethod
    def get_vendor_id(self) -> str:
        """Unique identifier, e.g. 'tenda', 'tplink', 'mikrotik', 'universal_arp'."""
        pass

    @abstractmethod
    def get_vendor_title(self) -> str:
        """Human-readable title, e.g. 'Tenda Wireless Router'."""
        pass

    @abstractmethod
    def test_connection(self) -> dict[str, Any]:
        """Test reachability and authentication to the router."""
        pass

    @abstractmethod
    def get_connected_devices(self) -> list[dict[str, Any]]:
        """Retrieve the live list of devices connected to the router."""
        pass

    @abstractmethod
    def block_device(self, ip_address: str, mac_address: str, hostname: str = "") -> dict[str, Any]:
        """Deny internet access for the specified device."""
        pass

    @abstractmethod
    def allow_device(self, ip_address: str, mac_address: str) -> dict[str, Any]:
        """Restore normal internet access for the specified device."""
        pass
