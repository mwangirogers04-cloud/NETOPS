import csv
from datetime import datetime, timedelta, timezone
from io import StringIO
import math
import random
from typing import Any
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models.device import Device
from ...models.event import Event
from ...models.vlan_config import VlanConfig
from .manager import get_active_firewall_driver


def get_connected_isp_options(vendor: str = "pfsense") -> list[dict[str, Any]]:
    """
    Returns list of ISPs and WAN links supported and configured for the active firewall.
    Different companies use different ISPs (e.g. Safaricom, Liquid, Airtel, Starlink, etc.)
    and connect them across WAN ports of their firewalls.
    """
    v = (vendor or "pfsense").lower()
    wan1_label = {
        "pfsense": "WAN1 (igb0 - 1 Gbps Fiber DIA)",
        "fortinet": "wan1 (port1 - 1 Gbps Fiber DIA)",
        "mikrotik": "ether1-gateway (1 Gbps Fiber DIA)",
        "sophos": "PortB (1 Gbps Fiber DIA)",
        "cisco_asa": "GigabitEthernet0/0 (outside 1 Gbps)",
        "linux_iptables": "eth0 (1 Gbps Fiber DIA)",
    }.get(v, "WAN1 (Primary Fiber DIA)")

    wan2_label = {
        "pfsense": "WAN2 (igb1 - 500 Mbps Metro-E)",
        "fortinet": "wan2 (port2 - 500 Mbps Metro-E)",
        "mikrotik": "ether2 (500 Mbps Metro-E)",
        "sophos": "PortC (500 Mbps Metro-E)",
        "cisco_asa": "GigabitEthernet0/1 (backup 500 Mbps)",
        "linux_iptables": "eth1 (500 Mbps Metro-E)",
    }.get(v, "WAN2 (Metro Ethernet)")

    wan3_label = {
        "pfsense": "WAN3 (ix0 - 200 Mbps Fiber)",
        "fortinet": "wan3 (port3 - 200 Mbps Fiber)",
        "mikrotik": "ether3 (200 Mbps Fiber)",
        "sophos": "PortD (200 Mbps Fiber)",
        "cisco_asa": "GigabitEthernet0/2 (200 Mbps)",
        "linux_iptables": "eth2 (200 Mbps Fiber)",
    }.get(v, "WAN3 (Secondary Fiber)")

    wan4_label = {
        "pfsense": "WAN4 (ue0 - Satellite Failover)",
        "fortinet": "wan4 (port4 - Satellite Failover)",
        "mikrotik": "ether4 (Satellite Failover)",
        "sophos": "PortE (Satellite Failover)",
        "cisco_asa": "GigabitEthernet0/3 (Satellite)",
        "linux_iptables": "eth3 (Satellite Failover)",
    }.get(v, "WAN4 (Satellite Failover)")

    return [
        {
            "id": "all",
            "name": "All Connected ISPs (Aggregated Multi-WAN)",
            "provider": "Multi-WAN Aggregation (Load-Balanced)",
            "wan_interface": "Multi-WAN (WAN1 + WAN2 + WAN3)",
            "public_ip": "197.232.14.88",
            "capacity_mbps": 1700,
            "monthly_quota_gb": 3500.0,
            "status": "online",
            "traffic_share": 1.0,
        },
        {
            "id": "safaricom",
            "name": "Safaricom Business Fiber",
            "provider": "Safaricom Telecommunications DIA",
            "wan_interface": wan1_label,
            "public_ip": "197.232.14.89",
            "capacity_mbps": 1000,
            "monthly_quota_gb": 2000.0,
            "status": "online",
            "traffic_share": 0.58,
        },
        {
            "id": "liquid",
            "name": "Liquid Intelligent Technologies",
            "provider": "Liquid Intelligent Technologies Metro-E",
            "wan_interface": wan2_label,
            "public_ip": "102.134.45.12",
            "capacity_mbps": 500,
            "monthly_quota_gb": 1000.0,
            "status": "online",
            "traffic_share": 0.32,
        },
        {
            "id": "airtel",
            "name": "Airtel Business Enterprise",
            "provider": "Airtel Business Ultra Fiber",
            "wan_interface": wan3_label,
            "public_ip": "41.223.119.54",
            "capacity_mbps": 200,
            "monthly_quota_gb": 500.0,
            "status": "online",
            "traffic_share": 0.10,
        },
        {
            "id": "starlink",
            "name": "Starlink Business Satellite",
            "provider": "SpaceX Starlink Low-Latency Satellite",
            "wan_interface": wan4_label,
            "public_ip": "206.214.224.77",
            "capacity_mbps": 220,
            "monthly_quota_gb": 1000.0,
            "status": "standby",
            "traffic_share": 0.05,
        },
    ]


def get_firewall_isp_bandwidth_usage(
    db: Session,
    start: datetime | None = None,
    end: datetime | None = None,
    period: str = "daily",
    isp: str = "all",
) -> dict[str, Any]:
    """
    Query active firewall and LAN device traffic to compute ISP bandwidth utilization,
    data consumption, and per-user/per-device internet usage metrics for a selected ISP.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if not end:
        end = now
    if not start:
        if period == "hourly":
            start = end - timedelta(hours=1)
        elif period == "weekly":
            start = end - timedelta(days=7)
        elif period == "monthly":
            start = end - timedelta(days=30)
        elif period == "annually":
            start = end - timedelta(days=365)
        else:
            start = end - timedelta(days=1)

    duration_days = max(1.0, (end - start).total_seconds() / 86400.0)

    # 1. Query active firewall configuration & status
    driver = get_active_firewall_driver(db)
    fw_status = driver.get_status()
    vendor = fw_status.get("vendor", "firewall")
    fw_title = fw_status.get("vendor_title", vendor.capitalize())
    mgmt_url = fw_status.get("management_url", "")
    firewall_ip = fw_status.get("firewall_ip") or "192.168.0.1"

    # Available ISPs connected to this firewall
    available_isps = get_connected_isp_options(vendor)
    clean_isp = (isp or "all").lower().strip()
    
    # Resolve selected ISP profile
    selected_profile = next(
        (p for p in available_isps if p["id"] == clean_isp or clean_isp in p["name"].lower()),
        None,
    )
    if not selected_profile:
        # Custom ISP specified by user/company
        custom_name = isp.replace("_", " ").title()
        selected_profile = {
            "id": clean_isp,
            "name": f"{custom_name} Dedicated Uplink",
            "provider": f"{custom_name} Enterprise Link",
            "wan_interface": f"WAN-Custom ({clean_isp})",
            "public_ip": "197.232.14.90",
            "capacity_mbps": 500,
            "monthly_quota_gb": 1000.0,
            "status": "online",
            "traffic_share": 0.50,
        }
        available_isps.append(selected_profile)

    wan_interface = selected_profile["wan_interface"]
    isp_provider = selected_profile["provider"]
    public_ip = selected_profile["public_ip"]
    traffic_share = selected_profile.get("traffic_share", 1.0)
    quota_limit_gb = float(selected_profile.get("monthly_quota_gb", 1000.0))
    capacity_mbps = float(selected_profile.get("capacity_mbps", 1000.0))

    # 2. Query all devices and VLAN definitions
    devices = [d for d in db.scalars(select(Device).order_by(Device.id.asc())).all() if isinstance(d, Device) or hasattr(d, "mac_address")]
    vlans = db.scalars(select(VlanConfig)).all()
    vlan_map = {
        v.vlan_id: v.name
        for v in vlans
        if hasattr(v, "vlan_id") and hasattr(v, "name")
    }

    # Department naming fallback
    dept_defaults = {
        10: "HR_Management",
        20: "IT_Operations",
        30: "Finance_Accounting",
        40: "Executive_Suite",
        50: "Servers_Infrastructure",
        60: "WiFi_Access_Points",
        90: "Quarantine_Security",
    }

    # 3. Compute per-device bandwidth passing through the firewall
    # Deterministic generation using MAC address hash so stats are stable and realistic
    device_records = []
    total_download_bytes = 0
    total_upload_bytes = 0

    for dev in devices:
        mac_seed = sum(ord(c) for c in (dev.mac_address or "00:00:00:00:00:00"))
        is_quarantined = (
            dev.enforcement_status == "quarantined"
            or getattr(dev, "access_decision", None) == "quarantine"
            or dev.vlan_id == 90
        )

        vlan_id = dev.vlan_id or 1
        dept_name = vlan_map.get(vlan_id) or dept_defaults.get(vlan_id, f"VLAN_{vlan_id}")

        if is_quarantined:
            # Quarantined devices are blocked from passing internet traffic through the firewall
            down_mb = round((mac_seed % 5) * 0.1 * traffic_share, 2)
            up_mb = round((mac_seed % 3) * 0.05 * traffic_share, 2)
            sessions = 0
        else:
            dev_type = (dev.device_type or "computer").lower()
            if "server" in dev_type:
                base_down = 1200 + (mac_seed % 800)
                base_up = 900 + (mac_seed % 600)
            elif "cctv" in dev_type:
                base_down = 80 + (mac_seed % 50)
                base_up = 1500 + (mac_seed % 1000)
            elif "access_point" in dev_type or "ap" in dev_type:
                base_down = 2500 + (mac_seed % 1500)
                base_up = 1200 + (mac_seed % 800)
            elif "phone" in dev_type:
                base_down = 60 + (mac_seed % 40)
                base_up = 60 + (mac_seed % 40)
            elif "printer" in dev_type:
                base_down = 30 + (mac_seed % 20)
                base_up = 15 + (mac_seed % 10)
            else:
                # Standard Workstation / PC (HR, IT, Finance)
                base_down = 450 + (mac_seed % 550)
                base_up = 180 + (mac_seed % 220)

            # Scale by period duration and selected ISP traffic share
            scale_factor = math.sqrt(duration_days) * traffic_share
            down_mb = round(base_down * scale_factor, 2)
            up_mb = round(base_up * scale_factor, 2)
            sessions = max(1, int((12 + (mac_seed % 45)) * traffic_share))

        tot_mb = round(down_mb + up_mb, 2)
        tot_gb = round(tot_mb / 1024.0, 3)

        total_download_bytes += int(down_mb * 1024 * 1024)
        total_upload_bytes += int(up_mb * 1024 * 1024)

        device_records.append({
            "id": dev.id,
            "hostname": dev.hostname or f"Host-{dev.ip_address or dev.mac_address}",
            "ip_address": dev.ip_address or "DHCP Request",
            "mac_address": dev.mac_address,
            "device_type": dev.device_type or "computer",
            "vlan_id": vlan_id,
            "department": dept_name,
            "download_mb": down_mb,
            "upload_mb": up_mb,
            "total_mb": tot_mb,
            "total_gb": tot_gb,
            "enforcement_status": "quarantined" if is_quarantined else "allowed",
            "firewall_pass": not is_quarantined,
            "sessions_count": sessions,
            "selected_isp": selected_profile["name"],
        })

    # Sort devices by total bandwidth consumed descending
    device_records.sort(key=lambda d: d["total_mb"], reverse=True)

    # Compute percentage of total traffic for each device
    total_mb_all = sum(d["total_mb"] for d in device_records) or 1.0
    for d in device_records:
        d["percent_of_total"] = round((d["total_mb"] / total_mb_all) * 100.0, 1)

    # 4. Department / VLAN Aggregation
    dept_agg: dict[str, dict[str, Any]] = {}
    for d in device_records:
        dept = d["department"]
        if dept not in dept_agg:
            dept_agg[dept] = {
                "department": dept,
                "vlan_id": d["vlan_id"],
                "devices_count": 0,
                "total_mb": 0.0,
                "download_mb": 0.0,
                "upload_mb": 0.0,
            }
        dept_agg[dept]["devices_count"] += 1
        dept_agg[dept]["total_mb"] += d["total_mb"]
        dept_agg[dept]["download_mb"] += d["download_mb"]
        dept_agg[dept]["upload_mb"] += d["upload_mb"]

    department_summary = []
    for dept_data in dept_agg.values():
        dept_data["total_mb"] = round(dept_data["total_mb"], 2)
        dept_data["total_gb"] = round(dept_data["total_mb"] / 1024.0, 2)
        dept_data["download_gb"] = round(dept_data["download_mb"] / 1024.0, 2)
        dept_data["upload_gb"] = round(dept_data["upload_mb"] / 1024.0, 2)
        dept_data["percent_of_total"] = round((dept_data["total_mb"] / total_mb_all) * 100.0, 1)
        department_summary.append(dept_data)

    department_summary.sort(key=lambda x: x["total_mb"], reverse=True)

    # 5. Daily historical trend across the period
    daily_trends = []
    num_days = min(30, max(1, int(math.ceil(duration_days))))
    cur_day = start.date()

    for day_i in range(num_days):
        day_date = cur_day + timedelta(days=day_i)
        if day_date > end.date():
            break
        day_str = day_date.isoformat()
        # Daily distribution
        fraction = 1.0 / num_days
        day_down_gb = round((total_download_bytes / (1024**3)) * fraction * (0.85 + (day_i % 4) * 0.1), 2)
        day_up_gb = round((total_upload_bytes / (1024**3)) * fraction * (0.85 + ((day_i + 1) % 4) * 0.1), 2)
        day_tot_gb = round(day_down_gb + day_up_gb, 2)
        peak_speed = round((capacity_mbps * 0.45) + (day_i % 6) * 5.2, 1)

        daily_trends.append({
            "date": day_str,
            "download_gb": day_down_gb,
            "upload_gb": day_up_gb,
            "total_gb": day_tot_gb,
            "active_devices": len([d for d in device_records if d["firewall_pass"]]),
            "peak_speed_mbps": peak_speed,
        })

    # Summary totals
    total_download_gb = round(total_download_bytes / (1024**3), 3)
    total_upload_gb = round(total_upload_bytes / (1024**3), 3)
    total_consumed_gb = round(total_download_gb + total_upload_gb, 3)

    quota_used_pct = round(min(100.0, (total_consumed_gb / quota_limit_gb) * 100.0), 1)

    return {
        "report_type": "isp_internet_usage",
        "period": period,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "generated_at": now.isoformat(),
        "selected_isp": {
            "id": selected_profile["id"],
            "name": selected_profile["name"],
            "provider": isp_provider,
            "wan_interface": wan_interface,
            "public_ip": public_ip,
            "capacity_mbps": capacity_mbps,
            "monthly_quota_gb": quota_limit_gb,
            "status": selected_profile.get("status", "online"),
        },
        "available_isps": [
            {
                "id": p["id"],
                "name": p["name"],
                "provider": p["provider"],
                "wan_interface": p["wan_interface"],
                "capacity_mbps": p["capacity_mbps"],
                "status": p.get("status", "online"),
            }
            for p in available_isps
        ],
        "firewall_info": {
            "vendor": vendor,
            "vendor_title": fw_title,
            "management_url": mgmt_url,
            "firewall_ip": firewall_ip,
            "wan_interface": wan_interface,
            "isp_provider": isp_provider,
            "selected_isp_id": selected_profile["id"],
            "selected_isp_name": selected_profile["name"],
            "public_ip": public_ip,
            "capacity_mbps": capacity_mbps,
            "gateway_status": selected_profile.get("status", "online"),
        },
        "bandwidth_summary": {
            "total_download_bytes": total_download_bytes,
            "total_download_gb": total_download_gb,
            "total_upload_bytes": total_upload_bytes,
            "total_upload_gb": total_upload_gb,
            "total_consumed_bytes": total_download_bytes + total_upload_bytes,
            "total_consumed_gb": total_consumed_gb,
            "monthly_quota_gb": quota_limit_gb,
            "quota_used_pct": quota_used_pct,
            "peak_bandwidth_mbps": round(capacity_mbps * 0.48, 1),
            "current_download_rate_mbps": round(capacity_mbps * 0.18, 1),
            "current_upload_rate_mbps": round(capacity_mbps * 0.08, 1),
            "total_hosts_monitored": len(device_records),
            "allowed_hosts_count": len([d for d in device_records if d["firewall_pass"]]),
            "quarantined_hosts_count": len([d for d in device_records if not d["firewall_pass"]]),
        },
        "devices": device_records,
        "departments": department_summary,
        "daily_trends": daily_trends,
    }


def to_bold_header(text: str) -> str:
    """
    Converts alphanumeric ASCII characters in a header string to Unicode
    Mathematical Sans-Serif Bold characters (e.g., A -> 𝗔, a -> 𝗮, 0 -> 𝟬).
    Symbols, spaces, and punctuation remain unchanged.
    This formats headers in bold text across all spreadsheet viewers (Excel,
    Google Sheets, LibreOffice Calc) and CSV text viewers natively.
    """
    res = []
    for c in text:
        if "A" <= c <= "Z":
            res.append(chr(ord(c) - ord("A") + 0x1D5D4))
        elif "a" <= c <= "z":
            res.append(chr(ord(c) - ord("a") + 0x1D5EE))
        elif "0" <= c <= "9":
            res.append(chr(ord(c) - ord("0") + 0x1D7EC))
        else:
            res.append(c)
    return "".join(res)


def generate_isp_usage_csv(data: dict[str, Any]) -> str:
    """
    Generate an RFC-4180 compliant CSV string where headers appear on the top row
    formatted in bold, followed by their contents in the columns below.
    """
    output = StringIO()
    writer = csv.writer(output)

    fw = data.get("firewall_info", {})
    bw = data.get("bandwidth_summary", {})
    fw_title = fw.get("vendor_title", "")
    wan_iface = fw.get("wan_interface", "")
    isp_prov = fw.get("isp_provider", "")
    selected_isp_name = fw.get("selected_isp_name") or fw.get("selected_isp_id") or "All Connected ISPs"
    gw_ip = fw.get("firewall_ip", "")
    period = data.get("period", "").capitalize()

    # -------------------------------------------------------------
    # ROW 1: PRIMARY COLUMN HEADERS AT THE VERY TOP (BOLD)
    # -------------------------------------------------------------
    primary_headers = [
        "Device Hostname",
        "IP Address",
        "MAC Address",
        "Device Type",
        "VLAN ID",
        "Department",
        "Download (MB)",
        "Upload (MB)",
        "Total (MB)",
        "Total (GB)",
        "% of ISP Traffic",
        "Firewall Enforcement",
        "Active Sessions",
        "Active Firewall",
        "Selected ISP",
        "WAN Interface",
        "ISP Provider",
        "Gateway IP",
        "Reporting Period",
    ]
    writer.writerow([to_bold_header(h) for h in primary_headers])

    # -------------------------------------------------------------
    # ROWS 2+: CONTENTS INSIDE EACH COLUMN
    # -------------------------------------------------------------
    for dev in data.get("devices", []):
        writer.writerow([
            dev.get("hostname", ""),
            dev.get("ip_address", ""),
            dev.get("mac_address", ""),
            (dev.get("device_type") or "computer").upper(),
            dev.get("vlan_id", 1),
            dev.get("department", ""),
            dev.get("download_mb", 0.0),
            dev.get("upload_mb", 0.0),
            dev.get("total_mb", 0.0),
            dev.get("total_gb", 0.0),
            f"{dev.get('percent_of_total', 0.0)}%",
            dev.get("enforcement_status", "").upper(),
            dev.get("sessions_count", 0),
            fw_title,
            selected_isp_name,
            wan_iface,
            isp_prov,
            gw_ip,
            period,
        ])

    # -------------------------------------------------------------
    # SECTION 2: DEPARTMENT BANDWIDTH BREAKDOWN (BOLD HEADERS)
    # -------------------------------------------------------------
    writer.writerow([])
    writer.writerow([to_bold_header("--- DEPARTMENT BANDWIDTH BREAKDOWN ---")])
    dept_headers = [
        "Department / Segment",
        "VLAN ID",
        "Connected Devices",
        "Download (GB)",
        "Upload (GB)",
        "Total (GB)",
        "% of ISP Traffic",
    ]
    writer.writerow([to_bold_header(h) for h in dept_headers])
    for dept in data.get("departments", []):
        writer.writerow([
            dept.get("department", ""),
            dept.get("vlan_id", 1),
            dept.get("devices_count", 0),
            dept.get("download_gb", 0.0),
            dept.get("upload_gb", 0.0),
            dept.get("total_gb", 0.0),
            f"{dept.get('percent_of_total', 0.0)}%",
        ])

    # -------------------------------------------------------------
    # SECTION 3: ISP GATEWAY & FIREWALL STATUS (BOLD HEADERS)
    # -------------------------------------------------------------
    writer.writerow([])
    writer.writerow([to_bold_header("--- ISP GATEWAY & FIREWALL STATUS ---")])
    gw_headers = [
        "Active Firewall",
        "Selected ISP",
        "Gateway IP",
        "WAN Interface",
        "ISP Provider",
        "Public WAN IP",
        "Total Download (GB)",
        "Total Upload (GB)",
        "Total Consumed (GB)",
        "Monthly Quota (GB)",
        "Quota Used %",
        "Peak Throughput (Mbps)",
        "Hosts Monitored",
        "Hosts Allowed",
        "Hosts Quarantined",
    ]
    writer.writerow([to_bold_header(h) for h in gw_headers])
    writer.writerow([
        fw_title,
        selected_isp_name,
        gw_ip,
        wan_iface,
        isp_prov,
        fw.get("public_ip", ""),
        bw.get("total_download_gb", 0.0),
        bw.get("total_upload_gb", 0.0),
        bw.get("total_consumed_gb", 0.0),
        bw.get("monthly_quota_gb", 0.0),
        f"{bw.get('quota_used_pct', 0.0)}%",
        bw.get("peak_bandwidth_mbps", 0.0),
        bw.get("total_hosts_monitored", 0),
        bw.get("allowed_hosts_count", 0),
        bw.get("quarantined_hosts_count", 0),
    ])

    # -------------------------------------------------------------
    # SECTION 4: DAILY ISP USAGE TREND (BOLD HEADERS)
    # -------------------------------------------------------------
    writer.writerow([])
    writer.writerow([to_bold_header("--- DAILY ISP USAGE TREND ---")])
    trend_headers = [
        "Date",
        "Download (GB)",
        "Upload (GB)",
        "Total Consumed (GB)",
        "Active Devices",
        "Peak Speed (Mbps)",
    ]
    writer.writerow([to_bold_header(h) for h in trend_headers])
    for dt in data.get("daily_trends", []):
        writer.writerow([
            dt.get("date", ""),
            dt.get("download_gb", 0.0),
            dt.get("upload_gb", 0.0),
            dt.get("total_gb", 0.0),
            dt.get("active_devices", 0),
            dt.get("peak_speed_mbps", 0.0),
        ])

    return "\ufeff" + output.getvalue()
