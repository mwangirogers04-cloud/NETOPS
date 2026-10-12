from unittest.mock import patch

import pytest

from backend.app.services.discovery import discover_devices


@pytest.mark.parametrize(
    "network",
    [
        "not-a-network",
        "192.168.1.5",
        "192.168.1.0/33",
        "",
    ],
)
def test_discovery_rejects_invalid_network_without_scanning(network):
    with patch(
        "backend.app.services.discovery.subprocess.run"
    ) as mock_run:
        with pytest.raises(ValueError):
            discover_devices(network)

    mock_run.assert_not_called()

def test_discovery_rejects_empty_network_without_scanning():
    from unittest.mock import patch

    with patch(
        "backend.app.services.discovery.subprocess.run"
    ) as mock_run:
        with pytest.raises(ValueError):
            discover_devices("")

    mock_run.assert_not_called()

def test_discovery_nmap_timeout():
    from unittest.mock import patch
    import subprocess

    with (
        patch(
            "backend.app.services.discovery.get_local_ip",
            return_value="192.168.1.10",
        ),
        patch(
            "backend.app.services.discovery.get_local_mac",
            return_value="AA:BB:CC:DD:EE:FF",
        ),
        patch(
            "backend.app.services.discovery.subprocess.run",
            side_effect=subprocess.TimeoutExpired(
                cmd="nmap",
                timeout=60,
            ),
        ) as mock_run,
    ):
        with pytest.raises(subprocess.TimeoutExpired):
            discover_devices("192.168.1.0/24")

    mock_run.assert_called_once()
