from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.main import app
from backend.app.services.sophos_enforcement import (
    is_sophos_configured,
    sophos_block_device,
    sophos_allow_device,
    sophos_test_connection,
    PROTECTED_IPS,
    GROUP_NAME,
)
from backend.app.models.device import Device
from backend.app.services.network_enforcement import enforce_device_access


client = TestClient(app)


def test_is_sophos_configured():
    with (
        patch.object(settings, "sophos_base_url", "https://192.168.0.10:4444"),
        patch.object(settings, "sophos_username", "Admin"),
        patch.object(settings, "sophos_password", "Secret123"),
    ):
        assert is_sophos_configured() is True

    with patch.object(settings, "sophos_password", ""):
        assert is_sophos_configured() is False


def test_sophos_block_device_protected_ips():
    for protected_ip in ["192.168.0.1", "192.168.0.10", "127.0.0.1", "192.168.0.13"]:
        res = sophos_block_device(protected_ip)
        assert res["status"] == "protected"
        assert "protected infrastructure IP" in res["reason"]


def test_sophos_block_device_unconfigured():
    with patch.object(settings, "sophos_password", ""):
        res = sophos_block_device("192.168.0.77")
        assert res["status"] == "simulated"


def test_sophos_block_device_success():
    fake_group_xml = f"""<Response APIVersion="1905.1">
      <IPHostGroup>
        <Name>{GROUP_NAME}</Name>
        <HostList>
          <Host>NETOPS_DUMMY_HOST</Host>
        </HostList>
      </IPHostGroup>
    </Response>"""

    with (
        patch.object(settings, "sophos_base_url", "https://192.168.0.10:4444"),
        patch.object(settings, "sophos_username", "Admin"),
        patch.object(settings, "sophos_password", "Secret123"),
        patch("backend.app.services.sophos_enforcement._send_sophos_xml") as mock_send,
    ):
        mock_send.return_value = fake_group_xml
        res = sophos_block_device("192.168.0.77", "TEST-PC")

        assert res["status"] == "blocked"
        assert res["ip_address"] == "192.168.0.77"
        assert res["host_name"] == "NETOPS_BLOCK_192_168_0_77"
        assert mock_send.call_count >= 2


def test_sophos_allow_device_success():
    fake_group_xml = f"""<Response APIVersion="1905.1">
      <IPHostGroup>
        <Name>{GROUP_NAME}</Name>
        <HostList>
          <Host>NETOPS_DUMMY_HOST</Host>
          <Host>NETOPS_BLOCK_192_168_0_77</Host>
        </HostList>
      </IPHostGroup>
    </Response>"""

    with (
        patch.object(settings, "sophos_base_url", "https://192.168.0.10:4444"),
        patch.object(settings, "sophos_username", "Admin"),
        patch.object(settings, "sophos_password", "Secret123"),
        patch("backend.app.services.sophos_enforcement._send_sophos_xml") as mock_send,
    ):
        mock_send.return_value = fake_group_xml
        res = sophos_allow_device("192.168.0.77")

        assert res["status"] == "allowed"
        assert res["ip_address"] == "192.168.0.77"
        assert mock_send.call_count >= 2


def test_sophos_test_connection_success():
    fake_rule_xml = """<Response APIVersion="1905.1">
      <Login><status>Authentication Successful</status></Login>
      <FirewallRule>
        <Name>NETOPS_Quarantine_Block</Name>
        <Status>Enable</Status>
      </FirewallRule>
    </Response>"""

    fake_group_xml = f"""<Response APIVersion="1905.1">
      <IPHostGroup>
        <Name>{GROUP_NAME}</Name>
        <HostList>
          <Host>NETOPS_DUMMY_HOST</Host>
          <Host>NETOPS_BLOCK_192_168_0_88</Host>
        </HostList>
      </IPHostGroup>
    </Response>"""

    with (
        patch.object(settings, "sophos_base_url", "https://192.168.0.10:4444"),
        patch.object(settings, "sophos_username", "Admin"),
        patch.object(settings, "sophos_password", "Secret123"),
        patch("backend.app.services.sophos_enforcement._send_sophos_xml") as mock_send,
    ):
        mock_send.side_effect = [fake_rule_xml, fake_group_xml]
        res = sophos_test_connection()

        assert res["connected"] is True
        assert res["api_version"] == "1905.1"
        assert res["quarantine_rule_active"] is True
        assert res["quarantined_hosts_count"] == 1
        assert "NETOPS_BLOCK_192_168_0_88" in res["quarantined_hosts"]


def test_sophos_api_routes():
    with (
        patch("backend.app.api.sophos.sophos_test_connection") as mock_test,
        patch("backend.app.api.sophos.sophos_block_device") as mock_block,
        patch("backend.app.api.sophos.sophos_allow_device") as mock_allow,
    ):
        mock_test.return_value = {"connected": True, "quarantined_hosts_count": 0}
        mock_block.return_value = {"status": "blocked", "ip_address": "192.168.0.55"}
        mock_allow.return_value = {"status": "allowed", "ip_address": "192.168.0.55"}

        # Live status
        resp = client.get("/sophos/live-status")
        assert resp.status_code == 200
        assert resp.json()["connected"] is True

        # Quarantine endpoint
        resp = client.post("/sophos/quarantine", json={"ip_address": "192.168.0.55", "hostname": "TEST-HOST"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "blocked"

        # Unquarantine endpoint
        resp = client.post("/sophos/unquarantine", json={"ip_address": "192.168.0.55"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "allowed"


def test_network_enforcement_triggers_sophos():
    device = Device(
        id=99,
        mac_address="AA:BB:CC:DD:EE:99",
        ip_address="192.168.0.99",
        hostname="WORKSTATION-1",
        device_type="workstation",
        approval_status="approved",
        enforcement_status="allowed",
        internet_access_authorized=False,  # Disallowed
        vlan_id=20,
    )
    db = MagicMock()
    db.scalar.return_value = None

    with (
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=True),
        patch("backend.app.services.network_enforcement.sophos_block_device") as mock_block,
        patch("backend.app.services.network_enforcement.create_event") as mock_event,
    ):
        mock_block.return_value = {"status": "blocked", "ip_address": "192.168.0.99"}

        res = enforce_device_access(device, db, force=True)

        assert res["decision"] == "quarantine"
        assert res["mode"] == "live_sophos"
        mock_block.assert_called_once_with("192.168.0.99", "WORKSTATION-1")


def test_network_enforcement_schedule_overrides_manual_disconnect():
    from backend.app.models.access_schedule import AccessSchedule
    device = Device(
        id=46,
        mac_address="F0:1F:AF:4C:6A:E9",
        ip_address="192.168.0.12",
        hostname="HOST-192-168-0-12",
        device_type="computer",
        approval_status="approved",
        enforcement_status="quarantined",
        internet_access_authorized=False,  # Manually disconnected previously
        vlan_id=20,
    )
    schedule = AccessSchedule(
        id=1,
        device_id=46,
        enabled=True,
        days="daily",
        start_time="08:00:00",
        end_time="17:00:00",
    )
    db = MagicMock()
    db.scalar.return_value = None
    db.query.return_value.filter.return_value.all.return_value = [schedule]

    with (
        patch("backend.app.services.network_enforcement.is_access_allowed", return_value=True),
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.create_event"),
    ):
        res = enforce_device_access(device, db, force=True)

        assert res["decision"] == "allowed"
        assert res["enforcement_status"] == "allowed"
        assert device.internet_access_authorized is True


def test_network_enforcement_schedule_quarantines_outside_window():
    from backend.app.models.access_schedule import AccessSchedule
    device = Device(
        id=46,
        mac_address="F0:1F:AF:4C:6A:E9",
        ip_address="192.168.0.12",
        hostname="HOST-192-168-0-12",
        device_type="computer",
        approval_status="approved",
        enforcement_status="allowed",
        internet_access_authorized=True,
        vlan_id=20,
    )
    schedule = AccessSchedule(
        id=1,
        device_id=46,
        enabled=True,
        days="daily",
        start_time="08:00:00",
        end_time="17:00:00",
    )
    db = MagicMock()
    db.scalar.return_value = None
    db.query.return_value.filter.return_value.all.return_value = [schedule]

    with (
        patch("backend.app.services.network_enforcement.is_access_allowed", return_value=False),
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.create_event"),
    ):
        res = enforce_device_access(device, db, force=True)

        assert res["decision"] == "quarantine"
        assert res["enforcement_status"] == "quarantined"
        assert device.internet_access_authorized is False
