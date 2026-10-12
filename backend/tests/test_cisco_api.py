from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_device_port_requires_cisco_credentials():
    with (
        patch.dict(
            "os.environ",
            {},
            clear=True,
        ),
    ):
        response = client.get("/cisco/devices/1/port")

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "Cisco access is not configured. "
        "Authorized switch credentials are required."
    )

def test_device_port_returns_404_when_device_missing():
    with (
        patch.dict(
            "os.environ",
            {
                "NETOPS_SWITCH_USERNAME": "test-user",
                "NETOPS_SWITCH_PASSWORD": "test-password",
                "NETOPS_SWITCH_MANAGEMENT_IP": "192.0.2.10",
            },
        ),
        patch(
            "backend.app.api.cisco.get_mac_address_table"
        ) as mock_mac_table,
    ):
        response = client.get("/cisco/devices/999999/port")

    assert response.status_code == 404
    assert response.json()["detail"] == "Device not found."
    mock_mac_table.assert_not_called()


def test_device_port_returns_matching_switch_port():
    from unittest.mock import MagicMock

    from backend.app.api.cisco import get_db

    test_device = MagicMock()
    test_device.id = 42
    test_device.mac_address = "AA:BB:CC:DD:EE:11"

    mock_db = MagicMock()
    mock_db.scalar.return_value = test_device

    def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db

    try:
        with (
            patch.dict(
                "os.environ",
                {
                    "NETOPS_SWITCH_USERNAME": "test-user",
                    "NETOPS_SWITCH_PASSWORD": "test-password",
                    "NETOPS_SWITCH_MANAGEMENT_IP": "192.0.2.10",
                },
            ),
            patch(
                "backend.app.api.cisco.get_mac_address_table",
                return_value=[
                    {
                        "vlan_id": 20,
                        "mac_address": "AA:BB:CC:DD:EE:11",
                        "type": "DYNAMIC",
                        "interface": "Gi0/10",
                    }
                ],
            ) as mock_mac_table,
        ):
            response = client.get("/cisco/devices/42/port")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200

    data = response.json()
    assert data["device_id"] == 42
    assert data["mac_address"] == "AA:BB:CC:DD:EE:11"
    assert data["management_ip"] == "192.0.2.10"
    assert data["mode"] == "read-only"
    assert data["lookup"]["identified"] is True
    assert data["lookup"]["switch_port"] == "Gi0/10"
    assert data["lookup"]["vlan_id"] == 20
    assert data["lookup"]["source"] == "supplied_mac_table"

    mock_mac_table.assert_called_once_with("192.0.2.10")

def test_device_port_reports_mac_not_found():
    from unittest.mock import MagicMock

    from backend.app.api.cisco import get_db

    test_device = MagicMock()
    test_device.id = 43
    test_device.mac_address = "11:22:33:44:55:66"

    mock_db = MagicMock()
    mock_db.scalar.return_value = test_device

    def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db

    try:
        with (
            patch.dict(
                "os.environ",
                {
                    "NETOPS_SWITCH_USERNAME": "test-user",
                    "NETOPS_SWITCH_PASSWORD": "test-password",
                    "NETOPS_SWITCH_MANAGEMENT_IP": "192.0.2.10",
                },
            ),
            patch(
                "backend.app.api.cisco.get_mac_address_table",
                return_value=[
                    {
                        "vlan_id": 20,
                        "mac_address": "AA:BB:CC:DD:EE:11",
                        "type": "DYNAMIC",
                        "interface": "Gi0/10",
                    }
                ],
            ),
        ):
            response = client.get("/cisco/devices/43/port")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200

    lookup = response.json()["lookup"]
    assert lookup["identified"] is False
    assert lookup["switch_port"] is None
    assert lookup["source"] == "supplied_mac_table"
    assert lookup["reason"] == (
        "Device MAC address not found in supplied MAC table"
    )


def test_cisco_status_reports_missing_configuration():
    with patch.dict("os.environ", {}, clear=True):
        response = client.get("/cisco/status")

    assert response.status_code == 200

    data = response.json()
    assert data["configured"] is False
    assert data["credentials_configured"] is False
    assert data["management_ip_configured"] is False
    assert data["connection_tested"] is False
    assert data["mode"] == "read-only"

def test_cisco_status_rejects_invalid_management_ip():
    with patch.dict(
        "os.environ",
        {
            "NETOPS_SWITCH_USERNAME": "test-user",
            "NETOPS_SWITCH_PASSWORD": "test-password",
            "NETOPS_SWITCH_MANAGEMENT_IP": "not-an-ip",
            "NETOPS_SWITCH_ALLOWED_IPS": "192.0.2.10",
        },
        clear=True,
    ):
        response = client.get("/cisco/status")

    data = response.json()
    assert data["management_ip_valid"] is False
    assert data["management_ip_approved"] is False
    assert data["configured"] is False


def test_cisco_status_rejects_unapproved_management_ip():
    with patch.dict(
        "os.environ",
        {
            "NETOPS_SWITCH_USERNAME": "test-user",
            "NETOPS_SWITCH_PASSWORD": "test-password",
            "NETOPS_SWITCH_MANAGEMENT_IP": "192.0.2.10",
            "NETOPS_SWITCH_ALLOWED_IPS": "192.0.2.20",
        },
        clear=True,
    ):
        response = client.get("/cisco/status")

    data = response.json()
    assert data["management_ip_valid"] is True
    assert data["management_ip_approved"] is False
    assert data["configured"] is False


def test_cisco_status_accepts_valid_approved_management_ip():
    with patch.dict(
        "os.environ",
        {
            "NETOPS_SWITCH_USERNAME": "test-user",
            "NETOPS_SWITCH_PASSWORD": "test-password",
            "NETOPS_SWITCH_MANAGEMENT_IP": "192.0.2.10",
            "NETOPS_SWITCH_ALLOWED_IPS": "192.0.2.10",
        },
        clear=True,
    ):
        response = client.get("/cisco/status")

    data = response.json()
    assert data["credentials_configured"] is True
    assert data["management_ip_valid"] is True
    assert data["management_ip_approved"] is True
    assert data["configured"] is True
    assert data["connection_tested"] is False


def test_device_port_returns_safe_error_when_switch_query_fails():
    from unittest.mock import MagicMock

    from backend.app.api.cisco import get_db

    test_device = MagicMock()
    test_device.id = 44
    test_device.mac_address = "AA:BB:CC:DD:EE:11"

    mock_db = MagicMock()
    mock_db.scalar.return_value = test_device

    def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db

    try:
        with (
            patch.dict(
                "os.environ",
                {
                    "NETOPS_SWITCH_USERNAME": "test-user",
                    "NETOPS_SWITCH_PASSWORD": "test-password",
                    "NETOPS_SWITCH_MANAGEMENT_IP": "192.0.2.10",
                },
            ),
            patch(
                "backend.app.api.cisco.get_mac_address_table",
                side_effect=RuntimeError(
                    "Simulated internal connection failure"
                ),
            ),
        ):
            response = client.get("/cisco/devices/44/port")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 502
    assert response.json()["detail"] == (
        "Unable to identify the device's Cisco switch port."
    )
    assert "Simulated internal connection failure" not in response.text


def test_interfaces_requires_credentials():
    with patch.dict("os.environ", {}, clear=True):
        response = client.get("/cisco/interfaces")

    assert response.status_code == 503


def test_vlans_requires_credentials():
    with patch.dict("os.environ", {}, clear=True):
        response = client.get("/cisco/vlans")

    assert response.status_code == 503


def test_mac_table_requires_credentials():
    with patch.dict("os.environ", {}, clear=True):
        response = client.get("/cisco/mac-table")

    assert response.status_code == 503


def test_interfaces_returns_safe_error_when_query_fails():
    with (
        patch.dict(
            "os.environ",
            {
                "NETOPS_SWITCH_USERNAME": "test-user",
                "NETOPS_SWITCH_PASSWORD": "test-password",
                "NETOPS_SWITCH_MANAGEMENT_IP": "192.0.2.10",
            },
        ),
        patch(
            "backend.app.api.cisco.get_interface_status",
            side_effect=RuntimeError("Simulated connection failure"),
        ),
    ):
        response = client.get("/cisco/interfaces")

    assert response.status_code == 502
    assert response.json()["detail"] == (
        "Unable to retrieve Cisco interface status."
    )
    assert "Simulated connection failure" not in response.text


def test_vlans_returns_safe_error_when_query_fails():
    with (
        patch.dict(
            "os.environ",
            {
                "NETOPS_SWITCH_USERNAME": "test-user",
                "NETOPS_SWITCH_PASSWORD": "test-password",
                "NETOPS_SWITCH_MANAGEMENT_IP": "192.0.2.10",
            },
        ),
        patch(
            "backend.app.api.cisco.get_vlan_brief",
            side_effect=RuntimeError("Simulated connection failure"),
        ),
    ):
        response = client.get("/cisco/vlans")

    assert response.status_code == 502
    assert response.json()["detail"] == (
        "Unable to retrieve Cisco VLAN information."
    )
    assert "Simulated connection failure" not in response.text


def test_mac_table_returns_safe_error_when_query_fails():
    with (
        patch.dict(
            "os.environ",
            {
                "NETOPS_SWITCH_USERNAME": "test-user",
                "NETOPS_SWITCH_PASSWORD": "test-password",
                "NETOPS_SWITCH_MANAGEMENT_IP": "192.0.2.10",
            },
        ),
        patch(
            "backend.app.api.cisco.get_mac_address_table",
            side_effect=RuntimeError("Simulated connection failure"),
        ),
    ):
        response = client.get("/cisco/mac-table")

    assert response.status_code == 502
    assert response.json()["detail"] == (
        "Unable to retrieve the Cisco MAC address table."
    )
    assert "Simulated connection failure" not in response.text
