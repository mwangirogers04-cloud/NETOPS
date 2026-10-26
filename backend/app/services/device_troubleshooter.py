"""
NETOPS Device Troubleshooting and Diagnostic Service.

Performs multi-layer diagnostics on LAN / WLAN machines to identify
root causes when devices are reported offline or unreachable:
1. Layer 2 Physical / ARP link status across local interfaces (eth0, wlan0).
2. MAC Address Tracking & DHCP IP Drift (checks if the physical device changed IP).
3. Layer 3 ICMP Ping with interface binding (eth0 vs wlan0 multi-homed routing).
4. Layer 4 TCP Port probing (checks if host is active despite ICMP firewall blocks).
5. Linux kernel neighbor table and routing state (ip route / ip neigh).
6. NETOPS Security Policy & VLAN Isolation (VLAN 90, isolation, firewall blocking).
7. Working hours & Device Access Schedule compliance.
8. Endpoint Update Agent telemetry health & freshness.
"""

from datetime import datetime, timezone
import os
import re
import shutil
import socket
import subprocess
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.device import Device
from ..models.endpoint_update import EndpointUpdate
from ..models.access_schedule import AccessSchedule
from ..models.event import Event
from .event_service import create_event
from .sophos_enforcement import is_sophos_configured
from .network_enforcement import enforce_device_access


def _find_binary(name: str) -> str:
    """Find binary path looking in PATH and standard system sbin directories."""
    found = shutil.which(name)
    if found:
        return found
    for prefix in ("/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin", "/bin"):
        p = os.path.join(prefix, name)
        if os.path.exists(p) and os.access(p, os.X_OK):
            return p
    return name


COMMON_PORTS_TO_PROBE = [
    (80, "HTTP Web Server"),
    (443, "HTTPS Web Server"),
    (22, "SSH Remote Shell"),
    (445, "SMB Windows File Sharing"),
    (3389, "RDP Remote Desktop"),
    (8291, "MikroTik Winbox Administration"),
    (53, "DNS Service"),
    (8080, "Alternative Web Server"),
]


def _probe_tcp_port(ip: str, port: int, timeout: float = 0.6) -> bool:
    """Attempt a fast non-blocking TCP connect to verify host activity."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def _check_arp_on_interface(ip: str, iface: str, timeout: int = 2) -> tuple[bool, str]:
    """Run arping using interface selection."""
    try:
        bin_path = _find_binary("arping")
        res = subprocess.run(
            [bin_path, "-c", "2", "-w", str(timeout), "-i", iface, ip],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout + 2,
        )
        if res.returncode == 0:
            return True, res.stdout.strip()
        return False, res.stderr.strip() or res.stdout.strip() or "No ARP reply received"
    except Exception as exc:
        return False, str(exc)


def _check_ping_on_interface(ip: str, iface: str, timeout: int = 2) -> tuple[bool, str]:
    """Run ICMP ping explicitly bound to an interface."""
    try:
        bin_path = _find_binary("ping")
        res = subprocess.run(
            [bin_path, "-I", iface, "-c", "2", "-W", str(timeout), ip],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout + 2,
        )
        if res.returncode == 0:
            return True, "ICMP Echo Reply received successfully"
        return False, "100% packet loss (timeout or host unreachable)"
    except Exception as exc:
        return False, str(exc)


def _scan_lan_mac_addresses() -> dict[str, dict[str, str]]:
    """
    Perform an active ARP scan across eth0 and wlan0 to map MAC -> {ip, interface, vendor}.
    Used to detect if a physical MAC changed IP address on DHCP.
    """
    discovered: dict[str, dict[str, str]] = {}

    bin_path = _find_binary("arp-scan")
    for iface in ("eth0", "wlan0"):
        try:
            res = subprocess.run(
                [bin_path, "--interface", iface, "--localnet", "--retry=1", "--timeout=500"],
                capture_output=True,
                text=True,
                check=False,
                timeout=6,
            )

            for line in res.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2 and ":" in parts[1] and len(parts[1].strip()) == 17:
                    ip_str = parts[0].strip()
                    mac_raw = parts[1].strip().upper()
                    mac_norm = mac_raw.replace(":", "").replace("-", "").upper()
                    vendor_str = " ".join(parts[2:]).strip() if len(parts) >= 3 else "LAN Device"
                    discovered[mac_norm] = {
                        "ip_address": ip_str,
                        "mac_address": mac_raw,
                        "vendor": vendor_str,
                        "interface": iface,
                    }
        except Exception:
            pass

    # Augment with kernel neighbor cache (ip neigh show)
    try:
        res = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
        for line in res.stdout.splitlines():
            parts = line.strip().split()
            if any(st in parts for st in ("REACHABLE", "PERMANENT", "STALE")):
                if len(parts) >= 1 and "lladdr" in parts:
                    idx = parts.index("lladdr")
                    if idx + 1 < len(parts):
                        mac_entry = parts[idx + 1].strip().replace(":", "").replace("-", "").upper()
                        if mac_entry not in discovered:
                            dev_iface = (
                                parts[parts.index("dev") + 1]
                                if "dev" in parts and parts.index("dev") + 1 < len(parts)
                                else "eth0"
                            )
                            discovered[mac_entry] = {
                                "ip_address": parts[0].strip(),
                                "mac_address": parts[idx + 1].strip().upper(),
                                "vendor": "LAN Device",
                                "interface": dev_iface,
                            }
    except Exception:
        pass

    return discovered


def _check_route(ip: str) -> tuple[bool, str, str | None]:
    """Check kernel route for destination IP."""
    try:
        res = subprocess.run(
            ["ip", "route", "get", ip],
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
        if res.returncode == 0:
            out = res.stdout.strip()
            # Extract dev
            dev_match = re.search(r"dev\s+([a-zA-Z0-9_-]+)", out)
            dev = dev_match.group(1) if dev_match else None
            return True, out, dev
        return False, res.stderr.strip() or "No route to host", None
    except Exception as exc:
        return False, str(exc), None


def _check_neighbor_state(ip: str) -> tuple[str, str]:
    """Check kernel neighbor state for IP."""
    try:
        res = subprocess.run(
            ["ip", "neigh", "show", ip],
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
        out = res.stdout.strip()
        if not out:
            return "NONE", "No ARP entry in kernel neighbor table"
        for st in ("REACHABLE", "PERMANENT", "STALE", "DELAY", "PROBE", "INCOMPLETE", "FAILED"):
            if st in out:
                return st, out
        return "UNKNOWN", out
    except Exception as exc:
        return "ERROR", str(exc)


def run_device_diagnostics(db: Session, device: Device) -> dict[str, Any]:
    """
    Execute exhaustive diagnostics for a specific device and formulate
    an actionable diagnosis report.
    """
    checks: list[dict[str, Any]] = []
    probable_causes: list[str] = []
    recommendations: list[str] = []

    dev_ip = device.ip_address
    dev_mac = device.mac_address
    norm_mac = dev_mac.replace(":", "").replace("-", "").upper() if dev_mac else None
    recorded_iface = getattr(device, "network_interface", None) or "eth0"

    # Active detection flags
    arp_success_iface: str | None = None
    ping_success_iface: str | None = None
    open_tcp_ports: list[int] = []
    detected_drift_ip: str | None = None
    detected_drift_iface: str | None = None

    # -------------------------------------------------------------
    # 1. ARP Resolution & Physical Link Check
    # -------------------------------------------------------------
    if dev_ip:
        for iface in ("eth0", "wlan0"):
            arp_ok, arp_detail = _check_arp_on_interface(dev_ip, iface)
            if arp_ok:
                arp_success_iface = iface
                checks.append({
                    "name": f"Layer 2 ARP Resolution ({iface})",
                    "status": "passed",
                    "details": f"Physical MAC responded on {iface} at {dev_ip}.",
                })
            else:
                checks.append({
                    "name": f"Layer 2 ARP Resolution ({iface})",
                    "status": "failed",
                    "details": f"No ARP response on {iface}: {arp_detail}",
                })
    else:
        checks.append({
            "name": "Layer 2 ARP Resolution",
            "status": "failed",
            "details": "Device has no IP address assigned in inventory.",
        })

    # -------------------------------------------------------------
    # 2. DHCP Drift & MAC Address Tracking
    # -------------------------------------------------------------
    mac_map = _scan_lan_mac_addresses()

    if norm_mac and norm_mac in mac_map:
        active_entry = mac_map[norm_mac]
        live_ip = active_entry.get("ip_address")
        live_iface = active_entry.get("interface")

        if live_ip and dev_ip and live_ip != dev_ip:
            detected_drift_ip = live_ip
            detected_drift_iface = live_iface
            checks.append({
                "name": "MAC Address Tracking & DHCP IP Drift",
                "status": "warning",
                "details": (
                    f"Physical hardware ({dev_mac}) was detected active on {live_iface} "
                    f"under new IP {live_ip} (system inventory has {dev_ip})."
                ),
            })
            probable_causes.append(
                f"DHCP IP Reassignment: The device renewed or acquired a new IP ({live_ip}) from the router, "
                f"while NETOPS still points to {dev_ip}."
            )
            recommendations.append(
                f"Update the device IP from {dev_ip} to {live_ip}, or configure a static DHCP reservation in your router."
            )
        elif live_ip and not dev_ip:
            detected_drift_ip = live_ip
            detected_drift_iface = live_iface
            checks.append({
                "name": "MAC Address Tracking & DHCP IP Drift",
                "status": "info",
                "details": f"Device hardware ({dev_mac}) is active at IP {live_ip}.",
            })
        else:
            checks.append({
                "name": "MAC Address Tracking & DHCP IP Drift",
                "status": "passed",
                "details": f"Hardware MAC {dev_mac} is actively confirmed at recorded IP {dev_ip}.",
            })
    else:
        checks.append({
            "name": "MAC Address Tracking & DHCP IP Drift",
            "status": "info",
            "details": f"MAC {dev_mac or 'Unknown'} not currently broadcasting in recent ARP table.",
        })

    # -------------------------------------------------------------
    # 3. Layer 3 ICMP Ping (Interface-bound)
    # -------------------------------------------------------------
    target_ip = detected_drift_ip or dev_ip
    if target_ip:
        for iface in ("eth0", "wlan0"):
            ping_ok, ping_detail = _check_ping_on_interface(target_ip, iface)
            if ping_ok:
                ping_success_iface = iface
                checks.append({
                    "name": f"Layer 3 ICMP Ping ({iface})",
                    "status": "passed",
                    "details": f"Ping replied successfully via {iface} to {target_ip}.",
                })
            else:
                checks.append({
                    "name": f"Layer 3 ICMP Ping ({iface})",
                    "status": "failed",
                    "details": f"Ping to {target_ip} failed on {iface}: {ping_detail}",
                })

    # -------------------------------------------------------------
    # 4. Layer 4 TCP Port Probing (Firewall Detection)
    # -------------------------------------------------------------
    if target_ip:
        tested_ports = []
        for port, service_name in COMMON_PORTS_TO_PROBE:
            if _probe_tcp_port(target_ip, port):
                open_tcp_ports.append(port)
                tested_ports.append(f"Port {port} ({service_name}) OPEN")

        if open_tcp_ports:
            checks.append({
                "name": "Layer 4 TCP Service Probing",
                "status": "passed",
                "details": f"Active services responding: {', '.join(tested_ports)}.",
            })
        else:
            checks.append({
                "name": "Layer 4 TCP Service Probing",
                "status": "info",
                "details": "Common management ports (80, 443, 22, 445, 8291, 3389) did not accept TCP connections.",
            })

    # -------------------------------------------------------------
    # 5. Routing & Kernel Neighbor State
    # -------------------------------------------------------------
    if dev_ip:
        has_route, route_info, route_dev = _check_route(dev_ip)
        neigh_state, neigh_info = _check_neighbor_state(dev_ip)

        if has_route:
            checks.append({
                "name": "Kernel Subnet Route Check",
                "status": "passed",
                "details": f"Route valid through interface '{route_dev or recorded_iface}': {route_info}",
            })
        else:
            checks.append({
                "name": "Kernel Subnet Route Check",
                "status": "failed",
                "details": f"No valid route to {dev_ip}: {route_info}",
            })
            probable_causes.append("Subnet / Gateway routing mismatch on host.")

        if neigh_state in ("REACHABLE", "PERMANENT"):
            checks.append({
                "name": "Kernel Neighbor Table State",
                "status": "passed",
                "details": f"Neighbor state is {neigh_state} ({neigh_info}).",
            })
        elif neigh_state in ("STALE", "DELAY"):
            checks.append({
                "name": "Kernel Neighbor Table State",
                "status": "info",
                "details": f"Neighbor state is {neigh_state} ({neigh_info}).",
            })
        else:
            checks.append({
                "name": "Kernel Neighbor Table State",
                "status": "failed",
                "details": f"Neighbor state is {neigh_state}: {neigh_info}",
            })

    # -------------------------------------------------------------
    # 6. Policy, VLAN Quarantine & Access Enforcement
    # -------------------------------------------------------------
    is_quarantined = (device.vlan_id == 90 or device.enforcement_status in ("quarantined", "isolated"))
    is_unapproved = (device.approval_status != "approved")

    if is_quarantined or is_unapproved:
        checks.append({
            "name": "NETOPS Access Policy & Quarantine",
            "status": "warning",
            "details": (
                f"Device is in Quarantine VLAN {device.vlan_id or 90} "
                f"(Approval: {device.approval_status}, Enforcement: {device.enforcement_status}). "
                f"External internet access is blocked."
            ),
        })
        probable_causes.append(
            f"Administrative Quarantine: Device is restricted to VLAN {device.vlan_id or 90} "
            f"with enforcement status '{device.enforcement_status}'."
        )
        recommendations.append(
            "Review and approve the device in LAN Device Inventory to assign an operational VLAN (e.g. VLAN 20 for Workstations)."
        )
    else:
        checks.append({
            "name": "NETOPS Access Policy & Quarantine",
            "status": "passed",
            "details": f"Device is approved on operational VLAN {device.vlan_id} with enforcement '{device.enforcement_status}'.",
        })

    # Access schedules
    try:
        schedules = db.scalars(
            select(AccessSchedule).where(
                AccessSchedule.device_id == device.id,
                AccessSchedule.enabled.is_(True),
            )
        ).all()
        if schedules:
            checks.append({
                "name": "Device Access Schedule",
                "status": "info",
                "details": f"{len(schedules)} active access schedule(s) configured for this device.",
            })
    except Exception:
        pass

    # -------------------------------------------------------------
    # 7. Endpoint Update Telemetry Health
    # -------------------------------------------------------------
    last_update_rep = db.scalars(
        select(EndpointUpdate)
        .where(
            (EndpointUpdate.mac_address == dev_mac)
            | (EndpointUpdate.ip_address == dev_ip)
            | (EndpointUpdate.hostname == device.hostname)
        )
        .order_by(EndpointUpdate.last_checked.desc())
    ).first()

    if last_update_rep and last_update_rep.last_checked:
        now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
        rep_dt = last_update_rep.last_checked.replace(tzinfo=None) if last_update_rep.last_checked.tzinfo else last_update_rep.last_checked
        age_min = max(0, int((now_dt - rep_dt).total_seconds() / 60))
        if age_min <= 15:
            checks.append({
                "name": "Endpoint Update Agent Telemetry",
                "status": "passed",
                "details": f"Agent is active and reported {age_min} minute(s) ago.",
            })
        else:
            checks.append({
                "name": "Endpoint Update Agent Telemetry",
                "status": "warning",
                "details": f"Agent has not reported for {age_min} minutes (stale telemetry).",
            })
            probable_causes.append(
                f"Endpoint agent inactive: No telemetry received from {device.hostname or 'machine'} in {age_min} minutes."
            )
            recommendations.append(
                "Ensure the NETOPS endpoint background update agent daemon is running on the host."
            )
    else:
        checks.append({
            "name": "Endpoint Update Agent Telemetry",
            "status": "info",
            "details": "No agent update telemetry reports on file for this machine.",
        })

    # -------------------------------------------------------------
    # 8. Synthesis & Diagnosed Verdict
    # -------------------------------------------------------------
    is_physically_live = bool(arp_success_iface or ping_success_iface or open_tcp_ports)

    can_auto_fix = False
    suggested_fix_action = None

    if detected_drift_ip and detected_drift_ip != dev_ip:
        diagnosed_status = "ip_mismatch"
        verdict = f"IP Address Changed (Detected at {detected_drift_ip})"
        summary = (
            f"The physical device (MAC {dev_mac}) is powered on and connected to the network on "
            f"{detected_drift_iface or 'LAN'}, but its IP address changed from {dev_ip} to {detected_drift_ip} via DHCP. "
            f"Because the inventory is configured with {dev_ip}, it is reported offline."
        )
        can_auto_fix = True
        suggested_fix_action = f"Update device IP to {detected_drift_ip} and set status to ONLINE"

    elif is_physically_live:
        if arp_success_iface and not ping_success_iface and not open_tcp_ports:
            diagnosed_status = "firewall_icmp_blocked"
            verdict = "Host is Online, but Firewall is Dropping Ping (ICMP)"
            summary = (
                f"The physical machine answered Layer 2 ARP requests on {arp_success_iface}, confirming it is "
                f"powered on and connected to the cable/Wi-Fi. However, it did not reply to ICMP ping or open TCP ports. "
                f"This typically indicates a client-side host firewall (e.g. Windows Defender Firewall, macOS stealth mode) "
                f"dropping ICMP Echo packets."
            )
            probable_causes.append("Client-side firewall blocking ICMP Echo requests (ping).")
            recommendations.append("Allow ICMP Echo Request in Windows Defender Firewall ('File and Printer Sharing: Echo Request - ICMPv4-In').")
            recommendations.append("Device is physically online and can be marked ONLINE.")
            can_auto_fix = True
            suggested_fix_action = "Mark device ONLINE in inventory"
        else:
            diagnosed_status = "online_reachable"
            verdict = "Device is Online and Reachable"
            summary = (
                f"Diagnostics confirmed that {device.hostname or dev_ip} is actively responding on "
                f"{ping_success_iface or arp_success_iface or recorded_iface}."
            )
            can_auto_fix = True
            suggested_fix_action = "Sync device status to ONLINE in inventory"

    elif is_quarantined and not is_physically_live:
        diagnosed_status = "offline_unreachable"
        verdict = "Machine Disconnected or Powered Off (In Quarantine VLAN 90)"
        summary = (
            f"Device {device.hostname or dev_ip} ({dev_mac}) did not respond to ARP, ICMP ping, or TCP connections on any interface. "
            f"The device appears to be unplugged, powered off, or disconnected from the Wi-Fi."
        )
        probable_causes.append("Machine is turned off, sleeping, or in power-save mode.")
        probable_causes.append("Ethernet cable disconnected or Wi-Fi radio disabled.")
        probable_causes.append("Device left the building or Wi-Fi coverage area.")
        recommendations.append("Verify power cable and power indicator lights on the physical machine.")
        recommendations.append("Ensure the network cable is securely plugged in or Wi-Fi is associated.")

    else:
        diagnosed_status = "offline_unreachable"
        verdict = "Device Disconnected or Powered Off"
        summary = (
            f"No physical link signals, ARP responses, or ICMP replies were received from {dev_ip or dev_mac} "
            f"on either eth0 (Ethernet) or wlan0 (Wi-Fi)."
        )
        probable_causes.append("Machine is powered off, hibernating, or sleeping.")
        probable_causes.append("Network cable is unplugged or Wi-Fi connection lost.")
        probable_causes.append("Device acquired a different IP address not yet in neighbor cache.")
        recommendations.append("Check if the physical machine is switched on.")
        recommendations.append("Verify network cable connection or Wi-Fi status on the device.")
        recommendations.append("Run a fresh LAN Discovery Scan if the device rebooted.")

    return {
        "device_id": device.id,
        "hostname": device.hostname,
        "mac_address": device.mac_address,
        "ip_address": device.ip_address,
        "network_interface": recorded_iface,
        "recorded_status": device.status,
        "diagnosed_status": diagnosed_status,
        "verdict": verdict,
        "summary": summary,
        "checks": checks,
        "probable_causes": probable_causes,
        "recommendations": recommendations,
        "detected_ip": detected_drift_ip,
        "detected_interface": detected_drift_iface or arp_success_iface or recorded_iface,
        "can_auto_fix": can_auto_fix,
        "suggested_fix_action": suggested_fix_action,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def apply_diagnostic_fix(db: Session, device: Device, action: str, new_ip: str | None = None) -> dict[str, Any]:
    """
    Apply a recommended automated fix from the diagnostic findings.
    """
    old_status = device.status
    old_ip = device.ip_address

    if action in ("sync_ip", "update_ip") and new_ip:
        device.ip_address = new_ip
        device.status = "online"
        device.last_seen = datetime.now(timezone.utc)
        
        # Also update endpoint_updates if present
        norm_mac = device.mac_address.replace(":", "").replace("-", "").upper() if device.mac_address else None
        if norm_mac:
            reps = db.scalars(
                select(EndpointUpdate).where(
                    (EndpointUpdate.mac_address == device.mac_address)
                    | (EndpointUpdate.hostname == device.hostname)
                )
            ).all()
            for r in reps:
                r.ip_address = new_ip

        try:
            enforce_device_access(device, db, force=True)
        except Exception:
            pass

        device.status = "online"
        device.last_seen = datetime.now(timezone.utc)


        create_event(
            db=db,
            event_type="device_diagnosed_ip_updated",
            message=(
                f"Automated diagnostic fix applied for {device.hostname or device.mac_address}: "
                f"IP address synchronized from {old_ip} to {new_ip}. Status set to ONLINE."
            ),
            device_id=device.id,
        )

        db.commit()
        db.refresh(device)
        return {
            "success": True,
            "message": f"Successfully updated IP from {old_ip} to {new_ip} and set status to ONLINE.",
            "device_id": device.id,
            "ip_address": device.ip_address,
            "status": device.status,
        }

    elif action in ("mark_online", "sync_status"):
        device.status = "online"
        device.last_seen = datetime.now(timezone.utc)

        try:
            enforce_device_access(device, db, force=True)
        except Exception:
            pass

        device.status = "online"
        device.last_seen = datetime.now(timezone.utc)


        create_event(
            db=db,
            event_type="device_diagnosed_marked_online",
            message=(
                f"Diagnostic recovery: Device {device.hostname or device.ip_address} ({device.mac_address}) "
                f"confirmed active via diagnostics and marked ONLINE."
            ),
            device_id=device.id,
        )

        db.commit()
        db.refresh(device)
        return {
            "success": True,
            "message": f"Device {device.hostname or device.ip_address} marked ONLINE successfully.",
            "device_id": device.id,
            "ip_address": device.ip_address,
            "status": device.status,
        }

    return {
        "success": False,
        "message": f"Unsupported diagnostic fix action: {action}",
    }
