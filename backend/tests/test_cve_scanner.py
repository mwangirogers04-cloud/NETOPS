"""
Unit and integration tests for Device Firmware & OS CVE Vulnerability Scanner.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.device import Device
from backend.app.models.device_vulnerability import DeviceVulnerability
from backend.app.services.cve_scanner_service import (
    evaluate_device_vulnerabilities,
    scan_device_for_cves,
    scan_all_devices_for_cves,
)

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def test_db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(test_db):
    app.dependency_overrides[get_db] = lambda: test_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def test_evaluate_device_vulnerabilities_linux():
    """Verify Linux server endpoint matches OpenSSH and Linux kernel CVEs."""
    dev = Device(
        hostname="srv-ubuntu-prod",
        vendor="Canonical / Linux",
        device_type="server",
        mac_address="00:11:22:33:44:55",
        ip_address="192.168.1.10",
    )
    findings = evaluate_device_vulnerabilities(dev)
    cve_ids = [f["cve_id"] for f in findings]
    assert "CVE-2024-6387" in cve_ids  # regreSSHion
    assert "CVE-2024-1086" in cve_ids  # Linux Kernel nf_tables
    top = findings[0]
    assert top["cvss_score"] >= 9.0
    assert top["severity"] == "CRITICAL"


def test_evaluate_device_vulnerabilities_windows():
    """Verify Windows machine matches Windows TCP/IP RCE CVE."""
    dev = Device(
        hostname="DESKTOP-WIN11-ENG",
        vendor="Microsoft Corporation",
        device_type="computer",
        mac_address="00:AA:BB:CC:DD:EE",
        ip_address="192.168.1.25",
    )
    findings = evaluate_device_vulnerabilities(dev)
    cve_ids = [f["cve_id"] for f in findings]
    assert "CVE-2024-38063" in cve_ids  # Windows TCP/IP RCE


def test_scan_device_for_cves_persists_to_db(test_db):
    """Verify that running a scan on a device saves findings in device_vulnerabilities table."""
    dev = Device(
        hostname="cam-lobby-hikvision",
        vendor="Hikvision Digital Technology",
        device_type="camera",
        mac_address="BC:54:51:11:22:33",
        ip_address="192.168.30.5",
        status="online",
        approval_status="approved",
        vlan_id=30,
    )
    test_db.add(dev)
    test_db.commit()
    test_db.refresh(dev)

    res = scan_device_for_cves(test_db, dev.id)
    assert res["overall_risk"] == "CRITICAL"
    assert res["max_cvss_score"] == 9.8
    assert res["vulnerabilities_count"] >= 1
    assert any(v["cve_id"] == "CVE-2021-36260" for v in res["vulnerabilities"])

    # Verify rows in DB
    stored = test_db.query(DeviceVulnerability).filter(DeviceVulnerability.device_id == dev.id).all()
    assert len(stored) >= 1
    assert stored[0].cve_id == "CVE-2021-36260"
    assert stored[0].severity == "CRITICAL"


def test_cve_scanner_api_endpoints(client, test_db):
    """Verify REST endpoints for single device and fleet CVE scanning."""
    dev = Device(
        hostname="cisco-core-sw",
        vendor="Cisco Systems",
        device_type="switch",
        mac_address="00:1B:D4:55:66:77",
        ip_address="192.168.0.2",
    )
    test_db.add(dev)
    test_db.commit()

    # 1. GET /devices/{id}/vulnerabilities (auto-scans on first get)
    r1 = client.get(f"/devices/{dev.id}/vulnerabilities")
    assert r1.status_code == 200
    d1 = r1.json()
    assert d1["device_id"] == dev.id
    assert d1["overall_risk"] == "CRITICAL"
    assert any(v["cve_id"] == "CVE-2023-20198" for v in d1["vulnerabilities"])

    # 2. POST /devices/{id}/scan-cve (on-demand re-scan)
    r2 = client.post(f"/devices/{dev.id}/scan-cve")
    assert r2.status_code == 200
    assert r2.json()["max_cvss_score"] == 10.0

    # 3. POST /devices/scan-cve-all (fleet scan)
    r3 = client.post("/devices/scan-cve-all")
    assert r3.status_code == 200
    d3 = r3.json()
    assert d3["total_devices_scanned"] >= 1
    assert "CRITICAL" in d3["risk_breakdown"]
