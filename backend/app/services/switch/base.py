from abc import ABC, abstractmethod
from typing import Any


class BaseSwitchDriver(ABC):
    """Abstract base class for all enterprise and simulated switch drivers."""

    def __init__(self, config: Any | None = None):
        self.config = config

    @abstractmethod
    def get_vendor_id(self) -> str:
        """Unique vendor identifier (e.g. 'cisco_ios', 'aruba', 'mikrotik', 'simulation')."""
        pass

    @abstractmethod
    def get_vendor_title(self) -> str:
        """Human-readable vendor title."""
        pass

    @abstractmethod
    def test_connection(self) -> dict[str, Any]:
        """Verify reachability and authentication to the switch."""
        pass

    @abstractmethod
    def get_vlans(self) -> list[dict[str, Any]]:
        """Retrieve the live list of VLANs configured on the switch."""
        pass

    @abstractmethod
    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        """Create a new VLAN on the switch."""
        pass

    @abstractmethod
    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        """Remove a VLAN from the switch."""
        pass

    @abstractmethod
    def get_interfaces(self) -> list[dict[str, Any]]:
        """Retrieve switch physical ports, operational statuses, and assigned VLANs."""
        pass

    @abstractmethod
    def set_port_vlan(
        self,
        port_name: str,
        vlan_id: int,
        mode: str = "access",
    ) -> dict[str, Any]:
        """Assign a physical switch interface to a specific VLAN."""
        pass

    @abstractmethod
    def get_running_config(self) -> str:
        """Retrieve the live running configuration text from the switch."""
        pass
