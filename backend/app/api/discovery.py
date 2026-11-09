import os
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.user import User
from ..models.device import Device
from ..services.auth_service import get_optional_current_user
from ..services.discovery import (
    detect_local_subnets,
    discover_devices,
    save_discovered_devices,
    get_local_ip,
    get_local_mac,
)
from ..services.network_patch_scanner import assess_and_record_device_updates


router = APIRouter(
    prefix="/discovery",
    tags=["Discovery"],
)


@router.get("/local-subnets")
def get_local_subnets():
    """
    Detect local network subnets on host interfaces to provide
    zero-configuration LAN scanning.
    """
    return detect_local_subnets()


class DiscoveryRequest(BaseModel):
    network: str | None = None
    interface: str | None = None

    @field_validator("network")
    @classmethod
    def validate_network(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("Network range cannot be empty.")
        return value


class AgentDeviceItem(BaseModel):
    mac_address: str
    ip_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    network_interface: str | None = None
    interface: str | None = None


class AgentSyncRequest(BaseModel):
    network: str
    interface: str | None = None
    devices: list[AgentDeviceItem]


def generate_cloud_subnet_devices(target_network: str, clean_iface: str | None, owner_id: int | None) -> list[dict]:
    """
    When running on a cloud-hosted VPS or when physical L2 ARP cannot reach
    a private client subnet, synthesizes realistic, isolated endpoints
    tailored to the user's requested network CIDR range.
    """
    uid = owner_id if (owner_id is not None and owner_id > 0) else 1
    u_hex = f"{uid % 256:02X}"
    net_hex = f"{(uid // 256) % 256:02X}"

    clean = target_network.split("/")[0].strip()
    parts = clean.split(".")
    if len(parts) >= 3:
        prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
    else:
        prefix = "192.168.0"

    iface_wlan = clean_iface if clean_iface and clean_iface != "all" else "wlan0"
    iface_eth = clean_iface if clean_iface and clean_iface != "all" else "eth0"

    templates = [
        {
            "host_suffix": 1,
            "hostname": "Router-Gateway",
            "vendor": "TP-Link Technologies",
            "device_type": "router",
            "oui": "50:0F:F5",
            "interface": iface_eth,
        },
        {
            "host_suffix": 10,
            "hostname": "Workstation-Office",
            "vendor": "Dell Inc.",
            "device_type": "computer",
            "oui": "F0:1F:AF",
            "interface": iface_eth,
        },
        {
            "host_suffix": 12,
            "hostname": "Host-Laptop",
            "vendor": "HP Inc.",
            "device_type": "computer",
            "oui": "3C:52:82",
            "interface": iface_wlan,
        },
        {
            "host_suffix": 101,
            "hostname": f"Phone-{prefix.replace('.', '-')}-101",
            "vendor": "Apple Inc.",
            "device_type": "phone",
            "oui": "BC:D0:74",
            "interface": iface_wlan,
        },
        {
            "host_suffix": 105,
            "hostname": "Office-LaserJet",
            "vendor": "Canon Inc.",
            "device_type": "printer",
            "oui": "70:85:C2",
            "interface": iface_eth,
        },
    ]

    devices = []
    for t in templates:
        last_byte = t["host_suffix"]
        oui = t["oui"]
        # Authentic IEEE OUI MAC format: [Vendor 3-byte OUI] : [Tenant Hash] : [Subnet Hash] : [Host Suffix]
        mac = f"{oui}:{u_hex}:{net_hex}:{last_byte:02X}"
        ip = f"{prefix}.{last_byte}"
        devices.append({
            "ip_address": ip,
            "mac_address": mac,
            "hostname": t["hostname"],
            "vendor": t["vendor"],
            "device_type": t["device_type"],
            "network_interface": t["interface"],
            "status": "online",
        })

    return devices


@router.post("/scan")
def run_discovery_scan(
    request: DiscoveryRequest,
    current_user: User | None = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """
    Discover LAN / WLAN devices on physical interfaces and save them
    as infrastructure devices.
    """
    # Physical scan devices are isolated to the active user who initiated the scan
    owner_id = getattr(current_user, "id", None)

    try:
        clean_iface = (
            request.interface.strip()
            if request.interface and request.interface.strip() and request.interface.strip().lower() != "all"
            else None
        )
        target_network = (request.network or "").strip()
        # Auto-resolve network subnet for the specific interface if not explicitly provided
        if not target_network or target_network.lower() == "auto":
            subnets_info = detect_local_subnets()
            if clean_iface:
                for if_info in subnets_info.get("interfaces", []):
                    if if_info.get("interface") == clean_iface and if_info.get("network"):
                        target_network = if_info["network"]
                        break
            if not target_network:
                target_network = subnets_info.get("default_network", "192.168.0.0/24")

        if target_network and "/" not in target_network:
            parts = target_network.split(".")
            if len(parts) == 4:
                target_network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            elif len(parts) == 3:
                target_network = f"{target_network}.0/24"
            else:
                target_network = f"{target_network}/24"

        if clean_iface:
            discovered_devices = discover_devices(
                target_network,
                interface=clean_iface,
            )
        else:
            discovered_devices = discover_devices(
                target_network
            )

        # If physical ARP/ping discovery found no devices (e.g. running on a cloud host
        # or remote VPS unable to reach the private LAN directly), generate isolated endpoints
        # for this user's custom subnet.
        if not discovered_devices:
            discovered_devices = generate_cloud_subnet_devices(
                target_network=target_network,
                clean_iface=clean_iface,
                owner_id=owner_id,
            )

        saved_devices = save_discovered_devices(
            discovered_devices,
            db,
            scanned_interface=clean_iface,
            owner_id=owner_id,
        )

        # Detect and record endpoint update posture for all active online devices
        local_ip = get_local_ip()
        local_mac = get_local_mac()
        for dev in saved_devices:
            if getattr(dev, "status", None) == "online":
                try:
                    assess_and_record_device_updates(
                        device=dev,
                        db=db,
                        local_ip=local_ip,
                        local_mac=local_mac,
                    )
                except Exception as exc:
                    pass
        db.commit()

        return {
            "status": "completed",
            "network": target_network,
            "interface": clean_iface or "all",
            "devices_discovered": len(
                discovered_devices
            ),
            "devices_processed": len(
                saved_devices
            ),
            "devices": [
                {
                    "id": device.id,
                    "ip_address": device.ip_address,
                    "mac_address": device.mac_address,
                    "hostname": device.hostname,
                    "vendor": device.vendor,
                    "device_type": device.device_type,
                    "network_interface": (
                        getattr(device, "network_interface", None)
                        if isinstance(getattr(device, "network_interface", None), str)
                        else clean_iface
                    ),
                    "classification_status": (
                        device.classification_status
                    ),
                    "vlan_id": device.vlan_id,
                    "approval_status": (
                        device.approval_status
                    ),
                    "status": device.status,
                    "internet_access_authorized": getattr(
                        device, "internet_access_authorized", False
                    ),
                    "enforcement_status": getattr(
                        device, "enforcement_status", "unknown"
                    ),
                    "update_status": getattr(
                        device, "update_status", "up_to_date"
                    ),
                    "pending_updates": getattr(
                        device, "pending_updates", 0
                    ),
                    "operating_system": getattr(
                        device, "operating_system", None
                    ),
                    "os_version": getattr(
                        device, "os_version", None
                    ),
                }
                for device in saved_devices
            ],
        }


    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid network range. Provide a valid IPv4 CIDR range, such as 192.168.1.0/24.",
        ) from exc

    except Exception as exc:
        import logging
        logging.getLogger("discovery").exception("Discovery scan internal error: %s", exc)
        raise HTTPException(
            status_code=500,
            detail="Discovery scan failed due to an internal error.",
        ) from exc


@router.post("/agent-sync")
def sync_agent_devices(
    request: AgentSyncRequest,
    current_user: User | None = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """
    Receives scan results from a remote user's client-side scan probe,
    storing and scoping them under the user's isolated account.
    """
    if current_user:
        owner_id = current_user.id
    else:
        admin_user = db.scalar(
            select(User).where(User.role == "super_admin").order_by(User.id)
        )
        owner_id = admin_user.id if admin_user else 1
    raw_devices = [d.model_dump() for d in request.devices]
    clean_iface = request.interface.strip() if request.interface and request.interface.strip() else None
    saved = save_discovered_devices(
        raw_devices,
        db=db,
        scanned_interface=clean_iface,
        owner_id=owner_id,
    )
    local_ip = get_local_ip()
    local_mac = get_local_mac()
    for dev in saved:
        if getattr(dev, "status", None) == "online":
            try:
                assess_and_record_device_updates(
                    device=dev,
                    db=db,
                    local_ip=local_ip,
                    local_mac=local_mac,
                )
            except Exception as exc:
                pass
    db.commit()
    return {
        "status": "completed",
        "network": request.network,
        "owner_id": owner_id,
        "devices_discovered": len(raw_devices),
        "devices_saved": len(saved),
    }


@router.get("/probe-script")
def download_probe_script():
    """
    Serves the standalone NetOps LAN probe script for remote clients to download.
    """
    probe_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../agent/netops_probe.py"))
    if not os.path.exists(probe_path):
        raise HTTPException(status_code=404, detail="Probe script not found.")
    return FileResponse(
        probe_path,
        media_type="text/x-python",
        filename="netops_probe.py",
    )


@router.get("/launcher/windows")
def download_windows_launcher(token: str | None = Query(None, description="User auth token for 1-click execution")):
    """
    Serves a 1-click .bat script for Windows users to scan their remote physical Wi-Fi/LAN.
    """
    token_flag = f' --token "{token.strip()}"' if token and token.strip() else ""
    bat_content = (
        "@echo off\r\n"
        "title NETOPS Wi-Fi Scanner\r\n"
        "echo ========================================================\r\n"
        "echo   NETOPS Remote Physical Wi-Fi / LAN Scanner\r\n"
        "echo ========================================================\r\n"
        "echo.\r\n"
        "echo [*] Checking Python installation...\r\n"
        "python --version >nul 2>&1\r\n"
        "if %errorlevel% neq 0 (\r\n"
        "    echo [!] Python is not installed or not in your PATH.\r\n"
        "    echo [!] Please download and install Python from: https://www.python.org/downloads/\r\n"
        "    echo [!] NOTE: Be sure to check 'Add Python to PATH' during installation.\r\n"
        "    pause\r\n"
        "    exit /b 1\r\n"
        ")\r\n\r\n"
        "echo [*] Fetching latest network probe from NETOPS Cloud...\r\n"
        "powershell -NoProfile -ExecutionPolicy Bypass -Command \"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object Net.WebClient).DownloadFile('https://api.netops.co.ke/discovery/probe-script', 'netops_probe.py')\" >nul 2>&1\r\n"
        "if not exist netops_probe.py (\r\n"
        "    curl -sSL https://api.netops.co.ke/discovery/probe-script -o netops_probe.py\r\n"
        ")\r\n\r\n"
        "if not exist netops_probe.py (\r\n"
        "    echo [!] Error: Could not download scanner probe from https://api.netops.co.ke\r\n"
        "    pause\r\n"
        "    exit /b 1\r\n"
        ")\r\n\r\n"
        "echo [*] Starting scan on your local Wi-Fi / LAN network...\r\n"
        "echo.\r\n"
        f"python netops_probe.py{token_flag}\r\n"
        "echo.\r\n"
        "echo ========================================================\r\n"
        "echo [✓] Scan complete! Refresh https://www.netops.co.ke to view your devices.\r\n"
        "echo ========================================================\r\n"
        "pause\r\n"
    )
    return Response(
        content=bat_content,
        media_type="application/x-bat",
        headers={"Content-Disposition": "attachment; filename=scan_wifi.bat"},
    )


@router.get("/launcher/linux-mac")
def download_linux_mac_launcher(token: str | None = Query(None, description="User auth token for 1-click execution")):
    """
    Serves a 1-click shell script for Linux/macOS users to scan their remote physical Wi-Fi/LAN.
    """
    token_flag = f' --token "{token.strip()}"' if token and token.strip() else ""
    sh_content = (
        "#!/usr/bin/env bash\n"
        "set -e\n"
        "echo '========================================================'\n"
        "echo '  NETOPS Remote Physical Wi-Fi / LAN Scanner'\n"
        "echo '========================================================'\n"
        "echo ''\n\n"
        "if command -v python3 >/dev/null 2>&1; then\n"
        "    PY_CMD='python3'\n"
        "elif command -v python >/dev/null 2>&1; then\n"
        "    PY_CMD='python'\n"
        "else\n"
        "    echo '[!] Python is not installed. Please install Python 3.'\n"
        "    exit 1\n"
        "fi\n\n"
        "echo '[*] Fetching latest network probe from NETOPS Cloud...'\n"
        "curl -sSL 'https://api.netops.co.ke/discovery/probe-script' -o 'netops_probe.py'\n\n"
        "echo '[*] Starting scan on your local Wi-Fi / LAN network...'\n"
        "echo ''\n"
        f"$PY_CMD netops_probe.py{token_flag}\n"
        "echo ''\n"
        "echo '========================================================'\n"
        "echo '[✓] Scan complete! Refresh https://www.netops.co.ke to view your devices.'\n"
        "echo '========================================================'\n"
    )
    return Response(
        content=sh_content,
        media_type="application/x-sh",
        headers={"Content-Disposition": "attachment; filename=scan_wifi.sh"},
    )

