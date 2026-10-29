from abc import ABC, abstractmethod
import logging
import socket
import time
from typing import Any

logger = logging.getLogger(__name__)

# Global switch reachability circuit breaker cache:
# key: "host:port" -> (is_reachable: bool, timestamp: float)
_SWITCH_REACHABILITY_CACHE: dict[str, tuple[bool, float]] = {}
REACHABILITY_CACHE_TTL = 30.0  # seconds (in seconds)


def check_switch_reachability(host: str, port: int = 22, timeout: float = 0.5) -> bool:
    """
    Ultra-fast TCP socket check with circuit breaker caching.
    Prevents blocking the web application for 15-30s when a hardware switch is offline or unreachable.
    """
    if not host:
        return False

    key = f"{host}:{port}"
    now = time.time()
    cached = _SWITCH_REACHABILITY_CACHE.get(key)
    if cached is not None:
        reachable, checked_at = cached
        if (now - checked_at) < REACHABILITY_CACHE_TTL:
            return reachable

    reachable = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        reachable = (result == 0)
    except Exception as exc:
        logger.debug("Socket reachability check failed for %s:%d: %s", host, port, exc)
        reachable = False

    _SWITCH_REACHABILITY_CACHE[key] = (reachable, now)
    return reachable


def invalidate_switch_reachability(host: str | None = None, port: int | None = None) -> None:
    """Clear cached reachability state when user explicitly tests or updates switch profile."""
    if host and port:
        _SWITCH_REACHABILITY_CACHE.pop(f"{host}:{port}", None)
    elif host:
        keys_to_remove = [k for k in _SWITCH_REACHABILITY_CACHE if k.startswith(f"{host}:")]
        for k in keys_to_remove:
            _SWITCH_REACHABILITY_CACHE.pop(k, None)
    else:
        _SWITCH_REACHABILITY_CACHE.clear()


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
