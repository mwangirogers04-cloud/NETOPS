from datetime import datetime, timezone
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.user import User
from backend.app.models.switch_config import SwitchConfig
from backend.app.models.vlan_config import VlanConfig
from backend.app.services.auth_service import hash_password, create_access_token


TEST_DB_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.pop(get_db, None)


def test_get_switch_vendors(client):
    """List of supported enterprise and simulated switch vendors."""
    res = client.get("/switches/vendors")
    assert res.status_code == 200
    vendors = res.json()
    vendor_ids = [v["id"] for v in vendors]
    assert "cisco_ios" in vendor_ids
    assert "aruba" in vendor_ids
    assert "mikrotik" in vendor_ids
    assert "simulation" in vendor_ids


def test_create_and_activate_switch_config(client, db_session):
    """Admin registers a Cisco Catalyst switch profile and activates it."""
    admin = User(
        username="switch_admin",
        email="switch_admin@netops.local",
        hashed_password=hash_password("Admin@1234"),
        role="admin",
        is_active=True,
        is_verified=True,
    )
    db_session.add(admin)
    db_session.commit()

    token = create_access_token({"sub": admin.username, "role": admin.role, "user_id": admin.id})

    # 1. Create switch profile
    create_res = client.post(
        "/switches/configs",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "vendor": "cisco_ios",
            "name": "Core Catalyst 2960-X",
            "management_ip": "192.168.0.2",
            "port": 22,
            "username": "netops",
            "password": "CiscoPassword123!",
            "enable_secret": "CiscoSecret123!",
            "is_active": True,
            "model": "Catalyst 2960-X",
            "total_ports": 24,
            "description": "Building A Main Distribution Switch",
        },
    )
    assert create_res.status_code == 200
    data = create_res.json()
    assert data["vendor"] == "cisco_ios"
    assert data["management_ip"] == "192.168.0.2"

    # 2. List switch configs
    list_res = client.get("/switches/configs")
    assert list_res.status_code == 200
    configs = list_res.json()
    assert len(configs) >= 1
    assert configs[0]["name"] == "Core Catalyst 2960-X"
    assert configs[0]["is_active"] is True


def test_switch_connection_test(client, db_session):
    """Admin tests reachability to a switch."""
    admin = User(
        username="net_engineer",
        email="engineer@netops.local",
        hashed_password=hash_password("Admin@1234"),
        role="admin",
        is_active=True,
        is_verified=True,
    )
    db_session.add(admin)
    db_session.commit()

    token = create_access_token({"sub": admin.username, "role": admin.role, "user_id": admin.id})

    res = client.post(
        "/switches/test-connection",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "vendor": "simulation",
            "management_ip": "192.168.0.2",
            "port": 22,
            "username": "admin",
            "password": "Password123!",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "Simulated Switch" in data["message"]


def test_list_and_create_vlan_on_switch(client, db_session):
    """Admin provisions a new VLAN (e.g. VLAN 25 Finance) to the switch."""
    admin = User(
        username="sec_admin",
        email="sec_admin@netops.local",
        hashed_password=hash_password("Admin@1234"),
        role="admin",
        is_active=True,
        is_verified=True,
    )
    db_session.add(admin)
    db_session.commit()

    token = create_access_token({"sub": admin.username, "role": admin.role, "user_id": admin.id})

    # 1. List initial VLANs
    list_res = client.get("/switches/vlans")
    assert list_res.status_code == 200
    vlans = list_res.json()
    vlan_ids = [v["vlan_id"] for v in vlans]
    assert 10 in vlan_ids  # VOIP
    assert 20 in vlan_ids  # COMPUTERS
    assert 90 in vlan_ids  # QUARANTINE

    # 2. Provision new VLAN 25
    create_res = client.post(
        "/switches/vlans",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "vlan_id": 25,
            "name": "Finance_Dept",
            "description": "Financial records and payroll network",
            "subnet": "192.168.25.0/24",
        },
    )
    assert create_res.status_code == 200
    res_data = create_res.json()
    assert res_data["success"] is True
    assert res_data["vlan_id"] == 25
    assert res_data["name"] == "Finance_Dept"

    # 3. Verify it appears in active VLANs
    list_after = client.get("/switches/vlans").json()
    after_ids = [v["vlan_id"] for v in list_after]
    assert 25 in after_ids


def test_delete_vlan_and_protect_reserved_vlans(client, db_session):
    """Cannot delete default VLAN 1 or Quarantine VLAN 90, but can delete custom VLAN."""
    admin = User(
        username="vlan_admin",
        email="vlan_admin@netops.local",
        hashed_password=hash_password("Admin@1234"),
        role="admin",
        is_active=True,
        is_verified=True,
    )
    db_session.add(admin)
    db_session.commit()

    token = create_access_token({"sub": admin.username, "role": admin.role, "user_id": admin.id})

    # 1. Attempting to delete VLAN 1 fails
    del_default = client.delete("/switches/vlans/1", headers={"Authorization": f"Bearer {token}"})
    assert del_default.status_code == 400
    assert "reserved" in del_default.json()["detail"].lower()

    # 2. Attempting to delete Quarantine VLAN 90 fails
    del_quarantine = client.delete("/switches/vlans/90", headers={"Authorization": f"Bearer {token}"})
    assert del_quarantine.status_code == 400
    assert "quarantine" in del_quarantine.json()["detail"].lower()

    # 3. Create and delete custom VLAN 75
    client.post(
        "/switches/vlans",
        headers={"Authorization": f"Bearer {token}"},
        json={"vlan_id": 75, "name": "Lab_Testing"},
    )
    del_custom = client.delete("/switches/vlans/75", headers={"Authorization": f"Bearer {token}"})
    assert del_custom.status_code == 200
    assert del_custom.json()["success"] is True


def test_assign_switch_port_vlan(client, db_session):
    """Admin reconfigures a physical switch port to a new VLAN without console cabling."""
    admin = User(
        username="port_admin",
        email="port_admin@netops.local",
        hashed_password=hash_password("Admin@1234"),
        role="admin",
        is_active=True,
        is_verified=True,
    )
    db_session.add(admin)
    db_session.commit()

    token = create_access_token({"sub": admin.username, "role": admin.role, "user_id": admin.id})

    # 1. Get initial port status
    ports_res = client.get("/switches/ports")
    assert ports_res.status_code == 200
    ports = ports_res.json()
    assert len(ports) >= 24

    # 2. Assign GigabitEthernet0/5 to VLAN 30 (CCTV)
    assign_res = client.post(
        "/switches/ports/assign",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "port_name": "GigabitEthernet0/5",
            "vlan_id": 30,
            "mode": "access",
        },
    )
    assert assign_res.status_code == 200
    assign_data = assign_res.json()
    assert assign_data["success"] is True
    assert assign_data["vlan_id"] == 30

    # 3. Verify in ports list
    ports_after = client.get("/switches/ports").json()
    p5 = next(p for p in ports_after if "0/5" in p["port"])
    assert p5["vlan"] == 30


def test_standard_user_forbidden_from_switch_configuration(client, db_session):
    """Standard users cannot create VLANs or reconfigure switch ports."""
    std_user = User(
        username="standard_user",
        email="standard@netops.local",
        hashed_password=hash_password("UserPass@1234"),
        role="user",
        is_active=True,
        is_verified=True,
    )
    db_session.add(std_user)
    db_session.commit()

    user_token = create_access_token({"sub": std_user.username, "role": std_user.role, "user_id": std_user.id})

    res = client.post(
        "/switches/vlans",
        headers={"Authorization": f"Bearer {user_token}"},
        json={"vlan_id": 88, "name": "Illegal_Vlan"},
    )
    assert res.status_code == 403


def test_cisco_sge2000_driver_and_vendor(client, db_session):
    """Test Cisco SGE2000 vendor profile and driver instantiation."""
    from backend.app.services.switch.manager import create_switch_driver
    from backend.app.services.switch.cisco_sge_driver import CiscoSgeSwitchDriver

    # Verify vendor listing includes Cisco SGE2000
    res = client.get("/switches/vendors")
    assert res.status_code == 200
    vendors = res.json()
    sge_vendor = next((v for v in vendors if v["id"] == "cisco_sge"), None)
    assert sge_vendor is not None
    assert "SGE2000" in sge_vendor["name"]

    # Test driver creation
    sge_cfg = {
        "vendor": "cisco_sge",
        "name": "Company SGE2000 Switch",
        "management_ip": "192.168.1.254",
        "port": 22,
        "username": "admin",
        "password": "secretpassword",
        "enable_secret": "",
    }
    driver = create_switch_driver(sge_cfg)
    assert isinstance(driver, CiscoSgeSwitchDriver)
    assert driver.get_vendor_id() == "cisco_sge"
    assert "cisco_s300" in driver._get_connection_params()["device_type"]

    # Test port normalization
    assert driver._normalize_port_name("1") == "ethernet g1"
    assert driver._normalize_port_name("g5") == "ethernet g5"
    assert driver._normalize_port_name("GigabitEthernet24") == "ethernet g24"


def test_multi_vendor_switch_drivers(client, db_session):
    """Test full multi-vendor driver registry including Ubiquiti, Juniper, Dell, TP-Link, Arista, etc."""
    from backend.app.services.switch.manager import create_switch_driver
    from backend.app.services.switch.enterprise_drivers import (
        UbiquitiSwitchDriver,
        JuniperSwitchDriver,
        AristaSwitchDriver,
        DellSwitchDriver,
        TpLinkSwitchDriver,
        DLinkSwitchDriver,
        HuaweiSwitchDriver,
        ExtremeBrocadeSwitchDriver,
        NetgearSwitchDriver,
        ZyxelSwitchDriver,
        ArubaSwitchDriver,
        MikrotikSwitchDriver,
    )

    # 1. Verify all 15 vendors are advertised in the endpoint
    res = client.get("/switches/vendors")
    assert res.status_code == 200
    vendors = res.json()
    vendor_ids = {v["id"] for v in vendors}

    expected_vendors = {
        "cisco_sge",
        "cisco_ios",
        "ubiquiti",
        "juniper",
        "arista",
        "dell",
        "tplink",
        "dlink",
        "huawei",
        "extreme",
        "netgear",
        "zyxel",
        "aruba",
        "mikrotik",
        "simulation",
    }
    for ev in expected_vendors:
        assert ev in vendor_ids, f"Expected vendor {ev} missing from /switches/vendors"

    # 2. Test Ubiquiti EdgeSwitch / UniFi Switch driver
    ubnt_driver = create_switch_driver({"vendor": "ubiquiti", "management_ip": "10.0.0.1"})
    assert isinstance(ubnt_driver, UbiquitiSwitchDriver)
    assert ubnt_driver.device_type == "ubiquiti_edgeswitch"
    res_ubnt = ubnt_driver.create_vlan(50, "CCTV_Ubiquiti")
    assert res_ubnt["success"] is True
    assert "vlan database" in res_ubnt["commands_applied"]

    # 3. Test Juniper Junos driver
    juniper_driver = create_switch_driver({"vendor": "juniper", "management_ip": "10.0.0.2"})
    assert isinstance(juniper_driver, JuniperSwitchDriver)
    assert juniper_driver.device_type == "juniper_junos"
    res_juniper = juniper_driver.create_vlan(60, "VoIP_Juniper")
    assert res_juniper["success"] is True
    assert any("set vlans" in cmd for cmd in res_juniper["commands_applied"])

    # 4. Test Dell EMC driver
    dell_driver = create_switch_driver({"vendor": "dell", "management_ip": "10.0.0.3"})
    assert isinstance(dell_driver, DellSwitchDriver)
    res_dell = dell_driver.create_vlan(70, "Servers_Dell")
    assert res_dell["success"] is True

    # 5. Test TP-Link driver
    tplink_driver = create_switch_driver({"vendor": "tplink", "management_ip": "10.0.0.4"})
    assert isinstance(tplink_driver, TpLinkSwitchDriver)
    res_tp = tplink_driver.create_vlan(80, "IoT_TPLink")
    assert res_tp["success"] is True

    # 6. Test Arista driver
    arista_driver = create_switch_driver({"vendor": "arista", "management_ip": "10.0.0.5"})
    assert isinstance(arista_driver, AristaSwitchDriver)
    res_arista = arista_driver.set_port_vlan("Ethernet1", 80, "access")
    assert res_arista["success"] is True


def test_assign_port_trunk_and_uplinks(client, db_session):
    """Test assigning individual trunk ports and auto-configuring the last 2 ports as uplinks."""
    admin = User(
        username="trunk_admin",
        email="trunk_admin@netops.local",
        hashed_password=hash_password("Admin@1234"),
        role="admin",
        is_active=True,
        is_verified=True,
    )
    db_session.add(admin)
    db_session.commit()

    token = create_access_token({"sub": admin.username, "role": admin.role, "user_id": admin.id})
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Assign single port as Trunk with tick box (is_trunk=True)
    res_single = client.post(
        "/switches/ports/assign",
        headers=headers,
        json={
            "port_name": "GigabitEthernet0/22",
            "vlan_id": 1,
            "mode": "access",  # mode field overridden by is_trunk=True
            "is_trunk": True,
        },
    )
    assert res_single.status_code == 200
    data_single = res_single.json()
    assert data_single["success"] is True
    assert data_single["mode"] == "trunk"
    assert data_single["is_uplink"] is True

    # 2. Automatically configure the last two ports as Trunk Uplinks
    res_uplinks = client.post(
        "/switches/ports/configure-uplinks",
        headers=headers,
        json={"native_vlan": 1, "mode": "trunk"},
    )
    assert res_uplinks.status_code == 200
    data_uplinks = res_uplinks.json()
    assert data_uplinks["success"] is True
    assert len(data_uplinks["ports"]) == 2
    assert "23" in data_uplinks["ports"][0] or "24" in data_uplinks["ports"][0]
    assert "24" in data_uplinks["ports"][1] or "23" in data_uplinks["ports"][1]

    # 3. Verify in ports list that ports 23 and 24 are marked trunk uplinks
    ports_res = client.get("/switches/ports")
    assert ports_res.status_code == 200
    ports = ports_res.json()
    p23 = next((p for p in ports if "23" in p["port"]), None)
    p24 = next((p for p in ports if "24" in p["port"]), None)
    assert p23 is not None and p23["mode"] == "trunk"
    assert p24 is not None and p24["mode"] == "trunk"



