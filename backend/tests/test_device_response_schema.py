from datetime import datetime

from backend.app.schemas.device import DeviceResponse


def make_response(**overrides):
    values = {
        "id": 37,
        "mac_address": "02:4E:45:54:4F:01",
        "ip_address": "192.0.2.101",
        "hostname": "SIM-PC-01",
        "vendor": "Dell",
        "device_type": "computer",
        "switch_name": None,
        "switch_port": None,
        "vlan_id": 20,
        "notes": "NETOPS SIMULATION: fictional test device",
        "status": "online",
        "approval_status": "approved",
        "classification_status": "normal",
        "enforcement_status": "quarantined",
        "internet_access_authorized": False,
        "access_decision": "quarantine",
        "first_seen": datetime(2026, 10, 10, 10, 0, 0),
        "last_seen": datetime(2026, 10, 10, 10, 5, 0),
    }
    values.update(overrides)
    return DeviceResponse(**values)


def test_approved_device_without_authorization_has_correct_reason():
    response = make_response()

    assert response.access_reason == (
        "Internet access has not been explicitly authorized"
    )
    assert response.model_dump()["access_reason"] == (
        "Internet access has not been explicitly authorized"
    )


def test_authorized_but_quarantined_device_has_correct_reason():
    response = make_response(internet_access_authorized=True)

    assert response.access_reason == (
        "Internet access is currently quarantined "
        "by policy or schedule"
    )


def test_authorized_and_allowed_device_has_correct_reason():
    response = make_response(
        internet_access_authorized=True,
        enforcement_status="allowed",
        access_decision="allowed",
    )

    assert response.access_reason == (
        "Approved recognized device with internet access allowed"
    )
