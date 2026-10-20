import ipaddress
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


def get_local_ip():
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


def get_arp_scan_devices(network: str | None = None, interface: str | None = None) -> list[dict]:
    """
    Rapidly discover LAN devices using arp-scan.
    arp-scan directly issues Layer 2 ARP requests on the local wire, discovering
    all connected machines in 1-2 seconds even when firewalls block ICMP ping.
    """
    cmd = ["arp-scan"]
    target_iface = interface or get_default_interface()
    if target_iface:
        cmd.extend(["--interface", target_iface])

    if network:
        cmd.append(network)
    else:
        cmd.append("--localnet")

    cmd.extend(["--retry=2", "--timeout=800"])

    discovered = []
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=10)
        for line in res.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                ip_cand = parts[0].strip()
                mac_cand = parts[1].strip()
                vendor_cand = " ".join(parts[2:]).strip() if len(parts) >= 3 else None

                if is_valid_ip_address(ip_cand) and len(mac_cand) == 17 and ":" in mac_cand:
                    discovered.append({
                        "ip_address": ip_cand,
                        "mac_address": mac_cand.upper(),
                        "hostname": None,
                        "vendor": vendor_cand if vendor_cand and "unknown" not in vendor_cand.lower() else None,
                        "device_type": classify_device(
                            hostname=None,
                            vendor=vendor_cand,
                            mac_address=mac_cand.upper(),
                        ),
                    })
    except Exception as exc:
        print(f"[DISCOVERY] arp-scan discovery note: {exc}")

    return discovered


def detect_local_subnets() -> dict:
    """
    Detect local IPv4 subnets across network interfaces.
    Returns default network and detected interfaces.
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
                try:
                    net = ipaddress.ip_interface(cidr).network
                    detected.append({
                        "interface": iface,
                        "ip": cidr.split("/")[0],
                        "cidr": cidr,
                        "network": str(net),
                        "is_virtual": is_virtual,
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


def discover_devices(network: str):
    """
    Discover LAN devices using Nmap ARP discovery and the
    Linux neighbour table.

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

    local_ip = get_local_ip()
    local_mac = get_local_mac()

    command = [
        "nmap",
        "-sn",
        "-PR",
        "--max-retries",
        "3",
        network,
        "-oX",
        "-",
    ]

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
        arp_devices = get_arp_scan_devices(network=network)
        for arp_dev in arp_devices:
            mac = arp_dev["mac_address"]
            if mac in discovered_by_mac:
                existing = discovered_by_mac[mac]
                if not existing.get("ip_address") and arp_dev.get("ip_address"):
                    existing["ip_address"] = arp_dev["ip_address"]
                if not existing.get("vendor") and arp_dev.get("vendor"):
                    existing["vendor"] = arp_dev["vendor"]
            else:
                discovered_by_mac[mac] = arp_dev
    except Exception as exc:
        print(f"[DISCOVERY] Multi-vector ARP scan note: {exc}")

    # ---------------------------------------------------------
    # Process Linux neighbour-table fallback
    # ---------------------------------------------------------

    neighbor_devices = get_neighbor_devices()

    for neighbor in neighbor_devices:
        mac_address = neighbor["mac_address"]

        if mac_address in discovered_by_mac:
            existing = discovered_by_mac[mac_address]

            if not existing.get("ip_address"):
                existing["ip_address"] = neighbor["ip_address"]

            continue

        # If not discovered by nmap or arp-scan, verify reachability
        # rather than blindly accepting a stale ARP cache entry
        state = neighbor.get("state")
        ip_addr = neighbor.get("ip_address")
        iface = neighbor.get("interface")

        if state not in ("REACHABLE", "PERMANENT"):
            is_active = False
            if ip_addr:
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

        discovered_by_mac[mac_address] = neighbor

    return list(discovered_by_mac.values())


def save_discovered_devices(
    devices: list[dict],
    db: Session,
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
    # Mark missing devices offline
    # ---------------------------------------------------------

    for existing_device in existing_devices:
        dev_mac = (
            existing_device.mac_address.replace(":", "").replace("-", "").upper()
            if existing_device.mac_address
            else ""
        )
        if (
            existing_device.status == "online"
            and dev_mac not in discovered_macs
        ):
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

        detected_type = classify_device(
            hostname=hostname,
            vendor=vendor,
            mac_address=mac_address,
        )

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
            elif new_ip and not old_ip:
                existing_device.ip_address = new_ip

            if hostname:
                existing_device.hostname = hostname

            if vendor:
                existing_device.vendor = vendor

            existing_type = existing_device.device_type

            # -------------------------------------------------
            # Device previously had no classification
            # -------------------------------------------------

            if (
                detected_type != "unknown"
                and existing_type in (None, "unknown")
            ):
                existing_device.device_type = detected_type

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

            was_offline = (existing_device.status != "online")
            existing_device.status = "online"
            saved_devices.append(existing_device)

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
                classification_status="normal",
                status="online",
                approval_status="pending",
                vlan_id=get_vlan_for_device_type(
                    detected_type
                ),
            )

            db.add(new_device)
            db.flush()

            saved_devices.append(new_device)

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
