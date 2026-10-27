from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.device import Device
from backend.app.models.firewall_config import FirewallConfig
from backend.app.services.firewall.manager import (
    list_supported_vendors,
    create_driver_instance,
    get_active_firewall_driver,
    probe_firewall_connection,
)
from backend.app.services.auth_service import create_access_token
from backend.app.services.network_enforcement import enforce_device_access

client = TestClient(app)


def test_list_supported_vendors():
    vendors = list_supported_vendors()
    vendor_ids = {v["id"] for v in vendors}
    assert "sophos" in vendor_ids
    assert "fortinet" in vendor_ids
    assert "palo_alto" in vendor_ids
    assert "checkpoint" in vendor_ids
    assert "mikrotik" in vendor_ids
    assert "pfsense" in vendor_ids
    assert "cisco_asa" in vendor_ids
    assert "juniper_srx" in vendor_ids
    assert "sonicwall" in vendor_ids
    assert "watchguard" in vendor_ids
    assert "ubiquiti" in vendor_ids
    assert "aruba" in vendor_ids
    assert "huawei_usg" in vendor_ids
    assert "linux_iptables" in vendor_ids
    assert "simulation" in vendor_ids
    assert len(vendors) == 15


def test_enterprise_drivers_instantiation():
    for v_id in [
        "fortigate",
        "palo_alto",
        "checkpoint",
        "juniper_srx",
        "sonicwall",
        "watchguard",
        "ubiquiti",
        "aruba",
        "huawei_usg",
    ]:
        drv = create_driver_instance(
            vendor=v_id,
            management_url="https://192.168.1.254",
            username="admin",
            password="secret",
            api_key="token-123",
        )
        assert drv.is_configured() is True
        res_prot = drv.block_device("192.168.0.1")
        assert res_prot["status"] == "protected"


def test_fortinet_driver_mocked():
    driver = create_driver_instance(
        vendor="fortinet",
        management_url="https://192.168.1.1",
        api_key="mock-api-token",
    )
    assert driver.is_configured() is True
    assert driver.vendor == "fortinet"

    # Protected IP cannot be blocked
    res_protected = driver.block_device("192.168.0.1")
    assert res_protected["status"] == "protected"

    # Mock API request
    with patch.object(driver, "_api_request") as mock_api:
        mock_api.return_value = {"status": "success"}

        block_res = driver.block_device("192.168.0.55", "PC-TEST")
        assert block_res["status"] == "blocked"
        assert mock_api.call_count == 2  # Address create + group member add

        allow_res = driver.allow_device("192.168.0.55")
        assert allow_res["status"] == "allowed"


def test_mikrotik_driver_mocked():
    driver = create_driver_instance(
        vendor="mikrotik",
        management_url="https://192.168.0.11",
        username="admin",
        password="password123",
    )
    assert driver.is_configured() is True
    assert driver.vendor == "mikrotik"

    with patch.object(driver, "_rest_request") as mock_rest:
        # Existing query returns empty list
        mock_rest.side_effect = [
            [],  # existing query
            {".id": "*1"},  # put response
            [{".id": "*1", "address": "192.168.0.77"}],  # query for allow
            {},  # delete
        ]

        block_res = driver.block_device("192.168.0.77", "MIKROTIK-CLIENT")
        assert block_res["status"] == "blocked"
        assert "address-list" in block_res["message"]

        allow_res = driver.allow_device("192.168.0.77")
        assert allow_res["status"] == "allowed"


def test_pfsense_driver_mocked():
    driver = create_driver_instance(
        vendor="pfsense",
        management_url="https://192.168.1.1",
        api_key="api-key-test",
        password="secret-test",
    )
    assert driver.is_configured() is True
    assert driver.vendor == "pfsense"

    with patch.object(driver, "_request") as mock_req:
        mock_req.return_value = {"result": "ok"}

        block_res = driver.block_device("192.168.1.45")
        assert block_res["status"] == "blocked"

        allow_res = driver.allow_device("192.168.1.45")
        assert allow_res["status"] == "allowed"


def test_linux_iptables_driver():
    driver = create_driver_instance(vendor="linux_iptables")
    assert driver.is_configured() is True
    assert driver.vendor == "linux_iptables"

    block_res = driver.block_device("192.168.0.90")
    assert block_res["status"] == "blocked"

    status = driver.test_connection()
    assert status["connected"] is True

    allow_res = driver.allow_device("192.168.0.90")
    assert allow_res["status"] == "allowed"


def test_simulation_driver():
    driver = create_driver_instance(vendor="simulation")
    assert driver.is_configured() is True

    block_res = driver.block_device("192.168.0.120")
    assert block_res["status"] == "blocked"

    allow_res = driver.allow_device("192.168.0.120")
    assert allow_res["status"] == "allowed"


def test_firewall_api_get_vendors():
    response = client.get("/firewall/vendors")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 6


def test_firewall_api_config_and_test():
    admin_token = create_access_token({"sub": "admin", "role": "admin"})
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    dev_token = create_access_token({"sub": "developer", "role": "super_admin"})
    dev_headers = {"Authorization": f"Bearer {dev_token}"}

    # 1. Administrator is DENIED testing firewall credentials (403 Forbidden)
    res_admin_test = client.post("/firewall/test", headers=admin_headers, json={"vendor": "simulation"})
    assert res_admin_test.status_code == 403

    # 2. Super Administrator is ALLOWED testing firewall credentials (200 OK)
    res_test = client.post("/firewall/test", headers=dev_headers, json={"vendor": "simulation"})
    assert res_test.status_code == 200
    assert res_test.json()["connected"] is True

    # 3. Administrator is DENIED saving firewall configuration/secrets (403 Forbidden)
    payload = {
        "vendor": "simulation",
        "name": "Test Simulation Profile",
        "management_url": "simulation://internal",
        "is_active": True,
    }
    res_admin_save = client.post("/firewall/config", headers=admin_headers, json=payload)
    assert res_admin_save.status_code == 403

    # 4. Super Administrator is ALLOWED saving firewall configuration/secrets (200 OK)
    res_save = client.post("/firewall/config", headers=dev_headers, json=payload)
    assert res_save.status_code == 200
    assert res_save.json()["status"] == "success"
    cfg_id = res_save.json()["config_id"]

    # Get configuration
    res_get = client.get("/firewall/config")
    assert res_get.status_code == 200
    configs = res_get.json()["saved_configs"]
    assert any(c["name"] == "Test Simulation Profile" for c in configs)

    # Cleanup: restore active sophos profile if present and delete test record
    from backend.app.database import SessionLocal
    db = SessionLocal()
    try:
        db.query(FirewallConfig).filter(FirewallConfig.id == cfg_id).delete()
        sophos_c = db.query(FirewallConfig).filter(FirewallConfig.vendor == "sophos").first()
        if sophos_c:
            sophos_c.is_active = True
        db.commit()
    finally:
        db.close()


def test_firewall_api_quarantine_and_unquarantine():
    admin_token = create_access_token({"sub": "admin", "role": "admin"})
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Quarantine IP (Administrator allowed)
    res_q = client.post("/firewall/quarantine", headers=admin_headers, json={"ip_address": "192.168.0.222", "hostname": "TEST-HOST"})
    assert res_q.status_code == 200
    assert res_q.json()["status"] in ("blocked", "simulated", "error")

    # Unquarantine IP (Administrator allowed)
    res_uq = client.post("/firewall/unquarantine", headers=admin_headers, json={"ip_address": "192.168.0.222"})
    assert res_uq.status_code == 200
    assert res_uq.json()["status"] in ("allowed", "simulated", "error")
