import ipaddress
import os
import socket
import subprocess
import xml.etree.ElementTree as ET

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models.device import Device
from ..models.event import Event
from .event_service import create_event
from .vlan_policy import get_vlan_for_device_type
from .firewall.manager import get_active_firewall_driver
from .sophos_enforcement import (
    is_sophos_configured,
    sophos_allow_device,
    sophos_block_device,
)
from .l2_quarantine import restore_device_l2
from .network_enforcement import enforce_device_access

from .device_classifier import classify_device


def is_valid_ip_address(ip_address: str | None) -> bool:
    if not ip_address:
        return False

    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

DISCOVERY_INTERFACE = "eth0"


def get_default_interface() -> str:
    """Find the active physical network interface for the default route or local IP."""
    try:
        res = subprocess.run(
            ["ip", "-4", "route", "get", "8.8.8.8"],
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
        for line in res.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass

    try:
        res = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
        for line in res.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass

    return "eth0"


def is_wireless_interface(interface: str | None) -> bool:
    """Return True if the network interface is a wireless (Wi-Fi / WLAN) adapter."""
    if not interface:
        return False
    iface = interface.strip()
    if iface.startswith(("wlan", "wl", "wifi", "ath", "ra")):
        return True
    return os.path.isdir(f"/sys/class/net/{iface}/wireless") or os.path.isdir(
        f"/sys/class/net/{iface}/phy80211"
    )


def get_wireless_ssid(interface: str) -> str | None:
    """Attempt to read the connected Wi-Fi SSID for a wireless interface."""
    if not is_wireless_interface(interface):
        return None
    try:
        res = subprocess.run(
            ["iw", "dev", interface, "link"],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
        for line in res.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("SSID:"):
                return stripped.split("SSID:", 1)[1].strip() or None
    except Exception:
        pass
    try:
        res = subprocess.run(
            ["iwgetid", interface, "-r"],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
        ssid = res.stdout.strip()
        if ssid:
            return ssid
    except Exception:
        pass
    return None


def get_local_ip(interface: str | None = None):
    if interface and interface != "all":
        try:
            res = subprocess.run(
                ["ip", "-4", "-o", "addr", "show", "dev", interface, "scope", "global"],
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
            )
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and "/" in parts[3]:
                    return parts[3].split("/")[0]
        except Exception:
            pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
    finally:
        sock.close()

    return local_ip


def get_local_mac(interface: str | None = None) -> str | None:
    target_interface = interface or get_default_interface()

    try:
        result = subprocess.run(
            ["ip", "link", "show", target_interface],
            capture_output=True,
            text=True,
            check=True,
            timeout=3,
        )

        for line in result.stdout.splitlines():
            line = line.strip()

            if line.startswith("link/ether"):
                return line.split()[1].upper()
    except Exception as exc:
        print(f"[DISCOVERY] Note getting MAC on {target_interface}: {exc}")

    # Fallback to standard physical interfaces
    for alt in ("eth0", "wlan0", "enp0s3", "ens33"):
        if alt == target_interface:
            continue
        try:
            res = subprocess.run(
                ["ip", "link", "show", alt],
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
            )
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.startswith("link/ether"):
                    return line.split()[1].upper()
        except Exception:
            pass

    return None


def _run_arp_scan_on_interface(network: str | None, target_iface: str | None) -> list[dict]:
    cmd = ["arp-scan"]
    if target_iface:
        cmd.extend(["--interface", target_iface])

    if network:
        cmd.append(network)
    else:
        cmd.append("--localnet")

    is_wireless = is_wireless_interface(target_iface) if target_iface else False
    if is_wireless:
        # Smartphones (Android/iOS) on Wi-Fi use power-saving sleep (802.11 PSM / DTIM)
        # Using 4 retries and 1200ms timeout ensures sleeping phones wake up and respond
        cmd.extend(["--retry=4", "--timeout=1200"])
    else:
        cmd.extend(["--retry=2", "--timeout=800"])

    discovered = []
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=12)
        for line in res.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                ip_cand = parts[0].strip()
                mac_cand = parts[1].strip()
                vendor_cand = " ".join(parts[2:]).strip() if len(parts) >= 3 else None

                if is_valid_ip_address(ip_cand) and len(mac_cand) == 17 and ":" in mac_cand:
                    clean_vendor = vendor_cand if vendor_cand and "unknown" not in vendor_cand.lower() else None
                    dev_type = classify_device(
                        hostname=None,
                        vendor=clean_vendor,
                        mac_address=mac_cand.upper(),
                    )
                    # Detect smartphone / mobile device with randomized/private Wi-Fi MAC
                    try:
                        first_byte = int(mac_cand.split(":")[0], 16)
                        if (first_byte & 0x02) and (is_wireless or not clean_vendor):
                            if not clean_vendor or "locally administered" in vendor_cand.lower():
                                clean_vendor = "Mobile Phone (Private Wi-Fi MAC)"
                            if dev_type == "unknown" or dev_type == "computer":
                                dev_type = "phone"
                    except Exception:
                        pass

                    dev_hostname = f"Phone-{ip_cand.replace('.', '-')}" if dev_type == "phone" else None

                    discovered.append({
                        "ip_address": ip_cand,
                        "mac_address": mac_cand.upper(),
                        "interface": target_iface,
                        "medium": "wireless" if is_wireless else "wired",
                        "hostname": dev_hostname,
                        "vendor": clean_vendor,
                        "device_type": dev_type,
                    })
    except Exception as exc:
        print(f"[DISCOVERY] arp-scan discovery note on {target_iface}: {exc}")

    return discovered


def get_arp_scan_devices(network: str | None = None, interface: str | None = None) -> list[dict]:
    """
    Rapidly discover LAN and WLAN (Wi-Fi) devices using arp-scan.
    arp-scan directly issues Layer 2 ARP requests on the local wire or wireless interface,
    discovering all connected machines in 1-2 seconds even when firewalls block ICMP ping.
    When interface is None or 'all', scans across all active physical interfaces (e.g. eth0 + wlan0).
    """
    if interface and interface != "all":
        return _run_arp_scan_on_interface(network, interface)

    target_ifaces: list[str] = []
    try:
        subnets_info = detect_local_subnets()
        for item in subnets_info.get("interfaces", []):
            if not item.get("is_virtual"):
                iface_name = item.get("interface")
                if iface_name and iface_name not in target_ifaces:
                    if not network or item.get("network") == network:
                        target_ifaces.append(iface_name)
    except Exception:
        pass

    if not target_ifaces:
        default_iface = get_default_interface()
        if default_iface:
            target_ifaces.append(default_iface)

    by_mac: dict[str, dict] = {}
    for iface in target_ifaces:
        for dev in _run_arp_scan_on_interface(network, iface):
            mac = dev["mac_address"]
            if mac not in by_mac:
                by_mac[mac] = dev
            else:
                if not by_mac[mac].get("vendor") and dev.get("vendor"):
                    by_mac[mac]["vendor"] = dev["vendor"]

    return list(by_mac.values())


def detect_local_subnets() -> dict:
    """
    Detect local IPv4 subnets across wired (LAN) and wireless (WLAN/Wi-Fi) network interfaces.
    Returns default network and detected interfaces with medium metadata.
    """
    detected = []
    try:
        cmd = ["ip", "-4", "-o", "addr", "show", "scope", "global"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                iface = parts[1]
                cidr = parts[3]
                is_virtual = iface.startswith(("docker", "br-", "veth", "virbr"))
                wireless = is_wireless_interface(iface)
                medium = "virtual" if is_virtual else ("wireless" if wireless else "wired")
                ssid = get_wireless_ssid(iface) if wireless else None
                if wireless:
                    label = f"Wi-Fi WLAN ({iface}{f' • {ssid}' if ssid else ''})"
                elif is_virtual:
                    label = f"Virtual ({iface})"
                else:
                    label = f"Wired LAN ({iface})"
                try:
                    net = ipaddress.ip_interface(cidr).network
                    detected.append({
                        "interface": iface,
                        "ip": cidr.split("/")[0],
                        "cidr": cidr,
                        "network": str(net),
                        "is_virtual": is_virtual,
                        "is_wireless": wireless,
                        "medium": medium,
                        "ssid": ssid,
                        "label": label,
                    })
                except Exception:
                    continue
    except Exception as exc:
        print(f"[DISCOVERY] Error detecting local subnets: {exc}")

    physical = [d for d in detected if not d["is_virtual"]]
    default_sub = (
        physical[0]["network"]
        if physical
        else (detected[0]["network"] if detected else "192.168.0.0/24")
    )
    return {
        "default_network": default_sub,
        "interfaces": detected,
    }


def get_neighbor_devices():
    """
    Read devices known by the Linux ARP/neighbour table.

    This acts as a fallback when subnet-wide Nmap discovery
    misses a device temporarily.
    """

    result = subprocess.run(
        [
            "ip",
            "neigh",
            "show",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    devices = []

    for line in result.stdout.splitlines():
        parts = line.split()

        if not parts:
            continue

        ip_address = parts[0]

        if "lladdr" not in parts:
            continue

        lladdr_index = parts.index("lladdr")

        if lladdr_index + 1 >= len(parts):
            continue

        mac_address = parts[lladdr_index + 1].upper()

        if len(mac_address) != 17:
            continue

        # Check neighbor state (last token in 'ip neigh show')
        state = parts[-1].upper() if len(parts) > lladdr_index + 1 else "UNKNOWN"
        dev_iface = parts[parts.index("dev") + 1] if "dev" in parts and parts.index("dev") + 1 < len(parts) else None

        # Exclude failed or incomplete resolution
        if state in ("FAILED", "INCOMPLETE"):
            continue

        devices.append(
            {
                "ip_address": ip_address,
                "mac_address": mac_address,
                "state": state,
                "interface": dev_iface,
                "hostname": None,
                "vendor": None,
                "device_type": "unknown",
            }
        )

    return devices


def discover_devices(network: str, interface: str | None = None):
    """
    Discover LAN and WLAN (Wi-Fi) devices using Nmap ARP discovery,
    arp-scan across wired/wireless interfaces, and the Linux neighbour table.

    Nmap provides vendor/hostname information where available.
    The Linux neighbour table acts as a fallback for devices
    that Nmap misses during a subnet-wide scan.
    """
    if not isinstance(network, str) or "/" not in network:
        raise ValueError(
            "A network range in CIDR notation is required."
        )

    try:
        parsed_network = ipaddress.ip_network(
            network,
            strict=False,
        )
    except ValueError as exc:
        raise ValueError(
            "A valid IPv4 or IPv6 network range is required."
        ) from exc

    if parsed_network.version != 4:
        raise ValueError(
            "Only IPv4 network ranges are supported for discovery."
        )

    network = str(parsed_network)
    specific_iface = (
        interface.strip()
        if interface and interface.strip() and interface.strip().lower() != "all"
        else None
    )

    if specific_iface:
        local_ip = get_local_ip(specific_iface)
        local_mac = get_local_mac(specific_iface)
    else:
        local_ip = get_local_ip()
        local_mac = get_local_mac()

    command = [
        "nmap",
        "-sn",
        "-PR",
        "--max-retries",
        "3",
    ]
    if specific_iface and os.path.exists(f"/sys/class/net/{specific_iface}"):
        command.extend(["--privileged", "-e", specific_iface])
    command.extend([
        network,
        "-oX",
        "-",
    ])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )

    root = ET.fromstring(result.stdout)

    discovered_by_mac = {}

    # ---------------------------------------------------------
    # Process Nmap results
    # ---------------------------------------------------------

    for host in root.findall("host"):
        status = host.find("status")

        if status is None or status.get("state") != "up":
            continue

        ip_address = None
        mac_address = None
        vendor = None
        hostname = None

        for address in host.findall("address"):
            addr_type = address.get("addrtype")

            if addr_type == "ipv4":
                ip_address = address.get("addr")

            elif addr_type == "mac":
                mac_address = address.get("addr")
                vendor = address.get("vendor")

        hostnames = host.find("hostnames")

        if hostnames is not None:
            hostname_entry = hostnames.find("hostname")

            if hostname_entry is not None:
                hostname = hostname_entry.get("name")

        if ip_address == local_ip and not mac_address:
            mac_address = local_mac
            vendor = "Local Machine"

        if not mac_address:
            continue

        mac_address = mac_address.upper()

        discovered_by_mac[mac_address] = {
            "ip_address": ip_address,
            "mac_address": mac_address,
            "interface": specific_iface,
            "medium": (
                "wireless"
                if specific_iface and is_wireless_interface(specific_iface)
                else ("wired" if specific_iface else None)
            ),
            "hostname": hostname,
            "vendor": vendor,
            "device_type": classify_device(
                hostname=hostname,
                vendor=vendor,
                mac_address=mac_address,
            ),
        }

    # ---------------------------------------------------------
    # Process Layer 2 ARP discovery (arp-scan)
    # ---------------------------------------------------------

    try:
        arp_devices = get_arp_scan_devices(network=network, interface=specific_iface)
        for arp_dev in arp_devices:
            mac = arp_dev["mac_address"]
            if mac in discovered_by_mac:
                existing = discovered_by_mac[mac]
                if not existing.get("ip_address") and arp_dev.get("ip_address"):
                    existing["ip_address"] = arp_dev["ip_address"]
                if not existing.get("vendor") and arp_dev.get("vendor"):
                    existing["vendor"] = arp_dev["vendor"]
                if not existing.get("interface") and arp_dev.get("interface"):
                    existing["interface"] = arp_dev["interface"]
                    existing["medium"] = arp_dev.get("medium")
            else:
                discovered_by_mac[mac] = arp_dev
    except Exception as exc:
        print(f"[DISCOVERY] Multi-vector ARP scan note: {exc}")

    # ---------------------------------------------------------
    # Process Linux neighbour-table fallback
    # ---------------------------------------------------------

    neighbor_devices = get_neighbor_devices()

    for neighbor in neighbor_devices:
        if specific_iface and neighbor.get("interface") != specific_iface:
            continue

        mac_address = neighbor["mac_address"]

        if mac_address in discovered_by_mac:
            existing = discovered_by_mac[mac_address]

            if not existing.get("ip_address"):
                existing["ip_address"] = neighbor["ip_address"]
            if not existing.get("interface") and neighbor.get("interface"):
                existing["interface"] = neighbor["interface"]
                existing["medium"] = "wireless" if is_wireless_interface(neighbor["interface"]) else "wired"

            continue

        # If not discovered by nmap or arp-scan, verify reachability
        # rather than blindly accepting a stale ARP cache entry
        state = neighbor.get("state")
        ip_addr = neighbor.get("ip_address")
        iface = specific_iface or neighbor.get("interface")

        if state not in ("REACHABLE", "PERMANENT"):
            is_active = False
            if ip_addr:
                try:
                    from .l2_quarantine import _currently_blocked_ips
                    if ip_addr in _currently_blocked_ips and state in ("STALE", "DELAY", "PROBE"):
                        is_active = True
                except Exception:
                    pass
            if not is_active and ip_addr:
                try:
                    probe_cmd = ["arping", "-c", "1", "-w", "1"]
                    if iface:
                        probe_cmd.extend(["-I", iface])
                    probe_cmd.append(ip_addr)
                    probe_res = subprocess.run(
                        probe_cmd,
                        capture_output=True,
                        check=False,
                        timeout=2,
                    )
                    if probe_res.returncode == 0:
                        is_active = True
                except Exception:
                    pass
            if not is_active:
                # Disconnected machine: do not add to discovered devices
                continue

        if (
            neighbor["ip_address"] == local_ip
            and mac_address == local_mac
        ):
            neighbor["vendor"] = "Local Machine"
            neighbor["device_type"] = "computer"

        else:
            neighbor["device_type"] = "unknown"

        neighbor["interface"] = iface
        neighbor["medium"] = "wireless" if is_wireless_interface(iface) else "wired"
        discovered_by_mac[mac_address] = neighbor

    # Ensure the local interface IP/MAC on specific_iface is present when scanning a live interface
    if specific_iface and local_ip and local_mac and os.path.exists(f"/sys/class/net/{specific_iface}"):
        norm_local_mac = local_mac.upper()
        if norm_local_mac not in discovered_by_mac:
            discovered_by_mac[norm_local_mac] = {
                "ip_address": local_ip,
                "mac_address": norm_local_mac,
                "interface": specific_iface,
                "medium": "wireless" if is_wireless_interface(specific_iface) else "wired",
                "hostname": socket.gethostname(),
                "vendor": "Local Machine",
                "device_type": "computer",
            }

    return list(discovered_by_mac.values())


def save_discovered_devices(
    devices: list[dict],
    db: Session,
    scanned_interface: str | None = None,
):
    """
    Save discovered devices and update their state.

    Existing database information is used to enrich devices
    discovered through the Linux neighbour-table fallback.

    Classification mismatches are flagged for manual review.

    Duplicate mismatch events are prevented when the same
    mismatch has already been recorded.
    """

    saved_devices = []

    discovered_macs = {
        device.get("mac_address", "").replace(":", "").replace("-", "").upper()
        for device in devices
        if device.get("mac_address")
    }

    existing_devices = db.scalars(
        select(Device)
    ).all()

    # ---------------------------------------------------------
    # Mark missing devices offline (scoped to scanned_interface if specified)
    # ---------------------------------------------------------

    for existing_device in existing_devices:
        if (
            scanned_interface
            and existing_device.network_interface
            and existing_device.network_interface != scanned_interface
        ):
            continue

        dev_mac = (
            existing_device.mac_address.replace(":", "").replace("-", "").upper()
            if existing_device.mac_address
            else ""
        )
        if (
            existing_device.status == "online"
            and dev_mac not in discovered_macs
        ):
            # Verify if device is actually unreachable before marking offline
            is_still_reachable = False
            if existing_device.ip_address:
                try:
                    res = subprocess.run(
                        ["ip", "neigh", "show", existing_device.ip_address],
                        capture_output=True,
                        text=True,
                        timeout=2,
                    )
                    for line in res.stdout.splitlines():
                        if any(st in line for st in ("REACHABLE", "DELAY", "PROBE", "STALE")):
                            is_still_reachable = True
                            break
                except Exception:
                    pass
                if not is_still_reachable:
                    preferred_iface = existing_device.network_interface or scanned_interface or "eth0"
                    try:
                        res = subprocess.run(
                            ["arping", "-c", "2", "-w", "1.5", "-I", preferred_iface, existing_device.ip_address],
                            capture_output=True,
                            timeout=3,
                        )
                        if res.returncode == 0:
                            is_still_reachable = True
                    except Exception:
                        pass

            if not is_still_reachable:
                existing_device.status = "offline"
                create_event(
                    db,
                    "device_offline",
                    (
                        f"Device {existing_device.hostname or existing_device.ip_address or dev_mac} "
                        f"({existing_device.mac_address}) went offline / disconnected from the LAN."
                    ),
                    existing_device.id,
                )

    # ---------------------------------------------------------
    # Process discovered devices
    # ---------------------------------------------------------

    for discovered in devices:
        mac_address = discovered.get("mac_address")

        if not mac_address:
            continue

        mac_address = mac_address.upper()
        ip_address = discovered.get("ip_address")

        if ip_address and not is_valid_ip_address(ip_address):
            print(
                f"[DISCOVERY] Ignoring invalid IP address: "
                f"{ip_address} "
                f"({mac_address})"
            )
            continue
        existing_device = db.scalar(
            select(Device).where(
                func.upper(Device.mac_address) == mac_address
            )
        )

        if existing_device and existing_device.mac_address != mac_address:
            existing_device.mac_address = mac_address

        hostname = discovered.get("hostname")
        vendor = discovered.get("vendor")

        # -----------------------------------------------------
        # Enrich information from existing database record
        # -----------------------------------------------------

        if existing_device:
            if not hostname:
                old_ip = existing_device.ip_address
                new_ip = discovered.get("ip_address")
                if (
                    existing_device.hostname
                    and old_ip
                    and new_ip
                    and existing_device.hostname == f"HOST-{old_ip.replace('.', '-')}"
                ):
                    hostname = f"HOST-{new_ip.replace('.', '-')}"
                else:
                    hostname = existing_device.hostname

            if not vendor:
                vendor = existing_device.vendor

        # -----------------------------------------------------
        # Classify device
        # -----------------------------------------------------

        detected_type = discovered.get("device_type")
        if not detected_type or detected_type == "unknown":
            detected_type = classify_device(
                hostname=hostname,
                vendor=vendor,
                mac_address=mac_address,
            )

        if detected_type == "phone":
            if not hostname or hostname.startswith("LAN-HOST-") or hostname.startswith("HOST-"):
                hostname = f"Phone-{ip_address.replace('.', '-')}"
            if not vendor or vendor == "LAN Device":
                vendor = discovered.get("vendor") or "Mobile Phone (Wi-Fi Private MAC)"

        # -----------------------------------------------------
        # Existing device
        # -----------------------------------------------------

        if existing_device:
            old_ip = existing_device.ip_address
            new_ip = discovered.get("ip_address")
            ip_changed = bool(new_ip and old_ip and old_ip != new_ip)

            if new_ip:
                other_devices = db.scalars(
                    select(Device).where(
                        Device.ip_address == new_ip,
                        func.upper(Device.mac_address) != mac_address,
                    )
                ).all()
                for other in other_devices:
                    other.ip_address = None

            if ip_changed:
                active_fw = get_active_firewall_driver(db)
                if active_fw.vendor != "sophos" and active_fw.is_configured() and old_ip:
                    try:
                        active_fw.allow_device(old_ip)
                    except Exception as exc:
                        print(f"[DISCOVERY] Error releasing old IP {old_ip} on {active_fw.vendor_title}: {exc}")
                elif is_sophos_configured() and old_ip:
                    try:
                        sophos_allow_device(old_ip)
                    except Exception as exc:
                        print(
                            f"[DISCOVERY] Error releasing old IP {old_ip} on Sophos: {exc}"
                        )
                if old_ip:
                    try:
                        restore_device_l2(old_ip)
                    except Exception:
                        pass

                existing_device.ip_address = new_ip
                create_event(
                    db,
                    "ip_address_changed",
                    (
                        f"Device IP address changed from {old_ip} to {new_ip} "
                        f"({existing_device.mac_address})"
                    ),
                    existing_device.id,
                )

                if getattr(existing_device, "ip_assignment", "dhcp") == "static":
                    create_event(
                        db,
                        "ip_address_conflict",
                        (
                            f"Static IP mismatch for {existing_device.hostname or existing_device.mac_address} "
                            f"({existing_device.mac_address}): Configured static IP was {old_ip}, but observed with {new_ip}. "
                            f"Manual review required."
                        ),
                        existing_device.id,
                    )
                else:
                    # DHCP device: Treat as a brand new machine accessing internet
                    existing_device.approval_status = "pending"
                    existing_device.internet_access_authorized = False
                    existing_device.vlan_id = 90
                    existing_device.enforcement_status = "quarantined"
                    create_event(
                        db,
                        "new_device",
                        (
                            f"Machine connected with new DHCP IP ({existing_device.network_interface or scanned_interface or 'eth0'}): "
                            f"{existing_device.hostname or 'LAN Device'} ({new_ip} / {existing_device.mac_address}) "
                            f"[{existing_device.vendor or 'LAN Endpoint'}] — "
                            f"Previous IP was {old_ip}. Treated as new machine: Placed in VLAN 90 Quarantine. Awaiting administrator review & approval."
                        ),
                        existing_device.id,
                    )
            elif new_ip and not old_ip:
                existing_device.ip_address = new_ip

            if hostname:
                existing_device.hostname = hostname

            if vendor:
                existing_device.vendor = vendor

            disc_iface = discovered.get("interface") or scanned_interface
            if disc_iface:
                existing_device.network_interface = disc_iface

            existing_type = existing_device.device_type

            # -------------------------------------------------
            # Device previously had no classification
            # -------------------------------------------------

            if (
                detected_type != "unknown"
                and existing_type in (None, "unknown")
            ):
                existing_device.device_type = detected_type

                if existing_device.approval_status != "pending":
                    existing_device.vlan_id = (
                        get_vlan_for_device_type(
                            detected_type
                        )
                    )

                existing_device.classification_status = (
                    "reviewed"
                )

                create_event(
                    db,
                    "device_classification",
                    (
                        f"Device classified as "
                        f"{detected_type}: "
                        f"{existing_device.ip_address} "
                        f"({existing_device.mac_address})"
                    ),
                    existing_device.id,
                )

            # -------------------------------------------------
            # Classification mismatch
            # -------------------------------------------------

            elif (
                detected_type != "unknown"
                and existing_type not in (None, "unknown")
                and existing_type != detected_type
            ):
                existing_device.classification_status = (
                    "review_required"
                )

                mismatch_message = (
                    f"Classification mismatch for device "
                    f"{existing_device.ip_address} "
                    f"({existing_device.mac_address}): "
                    f"existing={existing_type}, "
                    f"detected={detected_type}. "
                    f"Manual review required."
                )

                # ---------------------------------------------
                # Prevent duplicate mismatch events
                # ---------------------------------------------

                latest_mismatch = db.scalar(
                    select(Event)
                    .where(
                        Event.device_id == existing_device.id,
                        Event.event_type == (
                            "classification_mismatch"
                        ),
                    )
                    .order_by(Event.id.desc())
                    .limit(1)
                )

                if (
                    latest_mismatch is None
                    or latest_mismatch.message
                    != mismatch_message
                ):
                    create_event(
                        db,
                        "classification_mismatch",
                        mismatch_message,
                        existing_device.id,
                    )

            # -------------------------------------------------
            # Classification agrees with existing record
            # -------------------------------------------------

            elif (
                detected_type != "unknown"
                and existing_type == detected_type
            ):
                if existing_device.approval_status != "pending":
                    existing_device.vlan_id = (
                        get_vlan_for_device_type(
                            detected_type
                        )
                    )

                if (
                    existing_device.classification_status
                    != "review_required"
                ):
                    existing_device.classification_status = (
                        "normal"
                    )

            # Quarantined or isolated devices must read offline until authorized for internet
            is_quarantined_or_isolated = (
                existing_device.enforcement_status in ("quarantined", "isolated")
                or not getattr(existing_device, "internet_access_authorized", True)
            )
            if is_quarantined_or_isolated:
                existing_device.status = "offline"
            else:
                was_offline = (existing_device.status != "online")
                existing_device.status = "online"
                if was_offline:
                    create_event(
                        db,
                        "device_online",
                        (
                            f"Device {existing_device.hostname or existing_device.ip_address} "
                            f"({existing_device.mac_address}) reconnected and is back online on the LAN."
                        ),
                        existing_device.id,
                    )
            saved_devices.append(existing_device)

            if ip_changed:
                try:
                    enforce_device_access(existing_device, db, force=True)
                except Exception as exc:
                    print(
                        f"[DISCOVERY] Error re-enforcing device access for "
                        f"{existing_device.ip_address}: {exc}"
                    )

        # -----------------------------------------------------
        # New device
        # -----------------------------------------------------

        else:
            new_ip = discovered.get("ip_address")
            if new_ip:
                other_devices = db.scalars(
                    select(Device).where(
                        Device.ip_address == new_ip,
                        func.upper(Device.mac_address) != mac_address,
                    )
                ).all()
                for other in other_devices:
                    other.ip_address = None

            device_type = (
                None
                if detected_type == "unknown"
                else detected_type
            )

            new_device = Device(
                mac_address=mac_address,
                ip_address=discovered.get("ip_address"),
                hostname=hostname,
                vendor=vendor,
                device_type=device_type,
                network_interface=discovered.get("interface") or scanned_interface,
                classification_status="normal",
                status="offline",
                approval_status="pending",
                ip_assignment="dhcp",
                vlan_id=90,
                enforcement_status="quarantined",
                internet_access_authorized=False,
            )

            db.add(new_device)
            db.flush()

            saved_devices.append(new_device)

            try:
                enforce_device_access(new_device, db, force=True)
            except Exception:
                pass

            create_event(
                db,
                "new_device",
                (
                    f"New device discovered: "
                    f"{new_device.ip_address} "
                    f"({new_device.mac_address})"
                ),
                new_device.id,
            )

            if detected_type != "unknown":
                create_event(
                    db,
                    "device_classification",
                    (
                        f"New device classified as "
                        f"{detected_type}: "
                        f"{new_device.ip_address} "
                        f"({new_device.mac_address})"
                    ),
                    new_device.id,
                )

    db.commit()

    for device in saved_devices:
        db.refresh(device)

    return saved_devices
