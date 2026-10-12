from types import SimpleNamespace

from backend.app.api.devices import add_access_information


def make_device(**overrides):
    values = {
        "device_type": "computer",
        "approval_status": "approved",
        "enforcement_status": "quarantined",
        "internet_access_authorized": False,
        "access_decision": None,
        "access_reason": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_approved_device_without_internet_authorization():
    device = make_device()

    result = add_access_information(device)

    assert result.access_decision == "quarantine"
    assert result.access_reason == (
        "Internet access has not been explicitly authorized"
    )


def test_approved_authorized_device_still_quarantined():
    device = make_device(internet_access_authorized=True)

    result = add_access_information(device)

    assert result.access_decision == "quarantine"
    assert result.access_reason == (
        "Internet access is currently quarantined by policy or schedule"
    )


def test_approved_authorized_device_allowed():
    device = make_device(
        internet_access_authorized=True,
        enforcement_status="allowed",
    )

    result = add_access_information(device)

    assert result.access_decision == "allowed"
    assert result.access_reason == (
        "Approved recognized device with internet access allowed"
    )


def test_pending_device_remains_quarantined():
    device = make_device(approval_status="pending")

    result = add_access_information(device)

    assert result.access_decision == "quarantine"
    assert result.access_reason == "Pending administrator approval"


def test_unknown_device_type_has_clear_reason():
    device = make_device(
        device_type=None,
        internet_access_authorized=True,
    )

    result = add_access_information(device)

    assert result.access_decision == "quarantine"
    assert result.access_reason == "Unknown or unrecognized device type"
