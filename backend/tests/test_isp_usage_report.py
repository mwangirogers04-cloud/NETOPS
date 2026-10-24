from datetime import datetime
from io import BytesIO
from unittest.mock import MagicMock
import openpyxl
import pytest
from fastapi.testclient import TestClient

from backend.app.api import reports
from backend.app.main import app
from backend.app.models.device import Device
from backend.app.models.vlan_config import VlanConfig
from backend.app.services.firewall.isp_usage_service import (
    generate_isp_usage_csv,
    get_connected_isp_options,
    get_firewall_isp_bandwidth_usage,
)


client = TestClient(app)


def test_get_connected_isp_options():
    options = get_connected_isp_options("pfsense")
    assert len(options) >= 5
    ids = [o["id"] for o in options]
    assert "all" in ids
    assert "safaricom" in ids
    assert "liquid" in ids
    assert "airtel" in ids
    assert "starlink" in ids


def test_get_firewall_isp_bandwidth_usage_unit():
    mock_db = MagicMock()
    dev1 = Device(
        id=1,
        ip_address="192.168.10.15",
        mac_address="00:1A:2B:3C:4D:5E",
        hostname="PC-HR-01",
        device_type="computer",
        vlan_id=10,
        enforcement_status="allowed",
    )
    dev2 = Device(
        id=2,
        ip_address="192.168.20.25",
        mac_address="00:1A:2B:3C:4D:5F",
        hostname="SRV-DATABASE",
        device_type="server",
        vlan_id=50,
        enforcement_status="allowed",
    )
    dev3 = Device(
        id=3,
        ip_address="192.168.90.99",
        mac_address="00:1A:2B:3C:4D:99",
        hostname="ROGUE-LAPTOP",
        device_type="computer",
        vlan_id=90,
        enforcement_status="quarantined",
    )

    vlan_hr = VlanConfig(vlan_id=10, name="HR_Management", subnet="192.168.10.0/24")
    vlan_srv = VlanConfig(vlan_id=50, name="Servers_Infrastructure", subnet="192.168.50.0/24")

    def mock_scalars(query):
        mock_result = MagicMock()
        query_str = str(query)
        if "devices" in query_str.lower() or "device" in query_str.lower():
            mock_result.all.return_value = [dev1, dev2, dev3]
        elif "vlan" in query_str.lower():
            mock_result.all.return_value = [vlan_hr, vlan_srv]
        else:
            mock_result.all.return_value = []
        return mock_result

    mock_db.scalars.side_effect = mock_scalars

    # 1. Default / Aggregated ISP
    res = get_firewall_isp_bandwidth_usage(mock_db, period="daily", isp="all")

    assert res["report_type"] == "isp_internet_usage"
    assert "firewall_info" in res
    assert "wan_interface" in res["firewall_info"]
    assert "isp_provider" in res["firewall_info"]
    assert "bandwidth_summary" in res
    assert res["bandwidth_summary"]["total_consumed_gb"] >= 0
    assert len(res["devices"]) == 3
    assert len(res["departments"]) >= 2
    assert "available_isps" in res
    assert len(res["available_isps"]) >= 5

    # 2. Specific Safaricom ISP selection
    res_saf = get_firewall_isp_bandwidth_usage(mock_db, period="daily", isp="safaricom")
    assert res_saf["firewall_info"]["selected_isp_id"] == "safaricom"
    assert "Safaricom" in res_saf["firewall_info"]["selected_isp_name"]

    # 3. Custom Company ISP selection
    res_custom = get_firewall_isp_bandwidth_usage(mock_db, period="daily", isp="orange_telecom")
    assert res_custom["firewall_info"]["selected_isp_id"] == "orange_telecom"
    assert "Orange Telecom" in res_custom["firewall_info"]["selected_isp_name"]

    # Verify quarantined host has minimal/blocked traffic
    quarantined = next(d for d in res["devices"] if d["id"] == 3)
    assert quarantined["enforcement_status"] == "quarantined"
    assert quarantined["firewall_pass"] is False
    assert quarantined["sessions_count"] == 0

    # Verify CSV generator with headers on top row
    csv_out = generate_isp_usage_csv(res_saf)
    csv_lines = [l for l in csv_out.splitlines() if l.strip()]
    assert csv_lines[0].startswith("Device Hostname,IP Address,MAC Address")
    assert "Selected ISP" in csv_lines[0]
    assert "Safaricom" in csv_out
    assert "DEPARTMENT BANDWIDTH BREAKDOWN" in csv_out
    assert "ISP GATEWAY & FIREWALL STATUS" in csv_out


def test_api_isp_options_endpoint():
    response = client.get("/reports/isp-options")
    assert response.status_code == 200
    data = response.json()
    assert "active_firewall" in data
    assert "isps" in data
    assert len(data["isps"]) >= 5


def test_api_generate_isp_usage_report_with_selected_isp():
    mock_db = MagicMock()
    mock_res = MagicMock()
    mock_res.all.return_value = []
    mock_db.scalars.return_value = mock_res

    def override_get_db():
        yield mock_db

    app.dependency_overrides[reports.get_db] = override_get_db
    try:
        response = client.get("/reports/generate?report_type=isp_internet_usage&period=daily&date=2026-10-24&isp=liquid")
    finally:
        app.dependency_overrides.pop(reports.get_db, None)

    assert response.status_code == 200
    data = response.json()
    assert data["report_type"] == "isp_internet_usage"
    assert data["firewall_info"]["selected_isp_id"] == "liquid"
    assert "Liquid" in data["firewall_info"]["selected_isp_name"]


def test_api_isp_usage_dedicated_endpoint_with_isp():
    mock_db = MagicMock()
    mock_res = MagicMock()
    mock_res.all.return_value = []
    mock_db.scalars.return_value = mock_res

    def override_get_db():
        yield mock_db

    app.dependency_overrides[reports.get_db] = override_get_db
    try:
        response = client.get("/reports/isp-usage?period=weekly&isp=airtel")
    finally:
        app.dependency_overrides.pop(reports.get_db, None)

    assert response.status_code == 200
    data = response.json()
    assert data["report_type"] == "isp_internet_usage"
    assert data["period"] == "weekly"
    assert data["firewall_info"]["selected_isp_id"] == "airtel"
    assert "Airtel" in data["firewall_info"]["selected_isp_name"]


def test_api_isp_usage_csv_download_with_isp():
    mock_db = MagicMock()
    mock_res = MagicMock()
    mock_res.all.return_value = []
    mock_db.scalars.return_value = mock_res

    def override_get_db():
        yield mock_db

    app.dependency_overrides[reports.get_db] = override_get_db
    try:
        response = client.get("/reports/isp-usage/download/csv?period=daily&date=2026-10-24&isp=safaricom")
    finally:
        app.dependency_overrides.pop(reports.get_db, None)

    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    assert "attachment; filename=\"netops_isp_internet_usage_safaricom" in response.headers["content-disposition"]
    assert response.text.startswith("Device Hostname,IP Address,MAC Address")
    assert "Safaricom" in response.text


def test_api_isp_usage_excel_export_with_isp():
    dev = Device(
        id=1,
        ip_address="192.168.10.50",
        mac_address="AA:BB:CC:DD:EE:01",
        hostname="HOST-01",
        device_type="computer",
        vlan_id=10,
        enforcement_status="allowed",
    )
    mock_db = MagicMock()
    mock_res = MagicMock()
    mock_res.all.return_value = [dev]
    mock_db.scalars.return_value = mock_res

    def override_get_db():
        yield mock_db

    app.dependency_overrides[reports.get_db] = override_get_db
    try:
        response = client.get("/reports/export/excel?report_type=isp_internet_usage&period=daily&date=2026-10-24&isp=safaricom")
    finally:
        app.dependency_overrides.pop(reports.get_db, None)

    assert response.status_code == 200
    assert "spreadsheetml.sheet" in response.headers["content-type"]

    wb = openpyxl.load_workbook(BytesIO(response.content))
    expected_sheets = [
        "User Bandwidth Usage",
        "Department Breakdown",
        "ISP & Gateway Overview",
        "Daily Trends",
    ]
    for s in expected_sheets:
        assert s in wb.sheetnames
        ws = wb[s]
        assert ws.cell(1, 1).value is not None
        assert ws.freeze_panes == "A2"
    assert wb.active.title == "User Bandwidth Usage"

    # Verify Sheet 1 has Selected ISP in Row 1 headers
    ws_user = wb["User Bandwidth Usage"]
    assert ws_user.cell(1, 14).value == "Selected ISP"

    # Verify Sheet 3 ISP & Gateway Overview has column headers on top row
    ws_ov = wb["ISP & Gateway Overview"]
    assert ws_ov.cell(1, 1).value == "Active Firewall"
    assert ws_ov.cell(1, 2).value == "Selected ISP"
    assert ws_ov.cell(1, 3).value == "Gateway IP"


def test_api_isp_usage_pdf_export_with_isp():
    mock_db = MagicMock()
    mock_res = MagicMock()
    mock_res.all.return_value = []
    mock_db.scalars.return_value = mock_res

    def override_get_db():
        yield mock_db

    app.dependency_overrides[reports.get_db] = override_get_db
    try:
        response = client.get("/reports/export/pdf?report_type=isp_internet_usage&period=daily&date=2026-10-24&isp=safaricom")
    finally:
        app.dependency_overrides.pop(reports.get_db, None)

    assert response.status_code == 200
    assert "application/pdf" in response.headers["content-type"]
    assert len(response.content) > 1000
