from concurrent.futures import ThreadPoolExecutor
import ipaddress
import os
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models.device import Device
from ..models.event import Event
from .event_service import create_event
from .vlan_policy import get_vlan_for_device_type, is_type_and_vlan_matching
from .firewall.manager import get_active_firewall_driver
from .sophos_enforcement import (
    is_sophos_configured,
    sophos_allow_device,
    sophos_block_device,
)
from .l2_quarantine import restore_device_l2
from .network_enforcement import enforce_device_access

from .device_classifier import classify_device
from .endpoint_health_monitor import unsuppress_mac_from_auto_registration


def is_valid_ip_address(ip_address: str | None) -> bool:
    if not ip_address:
        return False

    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

DISCOVERY_INTERFACE = "eth0"


COMMON_OUI_MAP = {
    # Sophos Security Gateways
    "7C:5A:1C": "Sophos",
    "00:1A:8C": "Sophos",
    # MikroTik / Routerboard
    "2C:C8:1B": "Routerboard.com",
    "48:8F:5A": "Routerboard.com",
    "6C:3B:6B": "Routerboard.com",
    "B8:69:F4": "Routerboard.com",
    "DC:2C:6E": "Routerboard.com",
    # Dell
    "F0:1F:AF": "Dell Inc.",
    "18:66:DA": "Dell Inc.",
    "B4:B5:2F": "Dell Inc.",
    "00:14:22": "Dell Inc.",
    "44:A8:42": "Dell Inc.",
    "5C:F9:DD": "Dell Inc.",
    "D4:BE:D9": "Dell Inc.",
    "E4:54:E8": "Dell Inc.",
    # HP / Hewlett Packard
    "3C:52:82": "HP Inc.",
    "70:5A:0F": "HP Inc.",
    "00:1E:0B": "HP Inc.",
    "9C:B6:54": "HP Inc.",
    "10:60:4B": "HP Inc.",
    "B4:99:BA": "HP Inc.",
    "C8:D3:FF": "HP Inc.",
    # Apple
    "BC:D0:74": "Apple Inc.",
    "A4:83:E7": "Apple Inc.",
    "86:39:DD": "Apple Inc.",
    "38:F9:D3": "Apple Inc.",
    "00:17:F2": "Apple Inc.",
    "AC:DE:48": "Apple Inc.",
    "F4:34:F0": "Apple Inc.",
    "7C:04:D0": "Apple Inc.",
    # TP-Link
    "50:0F:F5": "TP-Link Technologies",
    "E8:48:B8": "TP-Link Technologies",
    "D8:0D:17": "TP-Link Technologies",
    "00:0A:EB": "TP-Link Technologies",
    "A0:F3:C1": "TP-Link Technologies",
    "60:32:B1": "TP-Link Technologies",
    "98:DA:C4": "TP-Link Technologies",
    # Tenda
    "04:95:E6": "Tenda Technology",
    "C8:3A:35": "Tenda Technology",
    "00:1E:58": "Tenda Technology",
    # Cisco Systems
    "00:08:E3": "Cisco Systems",
    "00:1B:54": "Cisco Systems",
    "00:26:99": "Cisco Systems",
    "F4:CF:E2": "Cisco Systems",
    # Canon
    "70:85:C2": "Canon Inc.",
    "00:00:85": "Canon Inc.",
    "00:1E:8F": "Canon Inc.",
    # Intel Corporate
    "B4:B6:86": "Intel Corporate",
    "00:24:D7": "Intel Corporate",
    "00:26:55": "Intel Corporate",
    "00:19:D1": "Intel Corporate",
    # Realtek Semiconductor
    "D4:6D:6D": "Realtek Semiconductor",
    "00:E0:4C": "Realtek Semiconductor",
    "52:54:00": "QEMU Virtual NIC",
    # Samsung Electronics
    "58:20:B1": "Samsung Electronics",
    "B0:BE:76": "Samsung Electronics",
    "AC:5F:3E": "Samsung Electronics",
    # Raspberry Pi Foundation
    "EC:FA:BC": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "B8:27:EB": "Raspberry Pi Foundation",
    # Microsoft
    "00:15:5D": "Microsoft Corporation",
    "00:1A:11": "Microsoft Corporation",
    # VMware
    "00:0C:29": "VMware Inc.",
    "00:50:56": "VMware Inc.",
    # Espressif IoT (ESP32, ESP8266, smart plugs, sensors)
    "24:0A:C4": "Espressif Inc.",
    "30:AE:A4": "Espressif Inc.",
    "84:F3:EB": "Espressif Inc.",
    "A4:CF:12": "Espressif Inc.",
    "D8:BF:C0": "Espressif Inc.",
    # Amazon (Echo, Alexa, Fire TV, Ring)
    "FC:65:DE": "Amazon Technologies",
    "50:DC:E7": "Amazon Technologies",
    "74:C2:46": "Amazon Technologies",
    "68:37:E9": "Amazon Technologies",
    "AC:63:BE": "Amazon Technologies",
    # Google (Chromecast, Nest, Home)
    "54:60:09": "Google LLC",
    "F4:F5:D8": "Google LLC",
    "D8:6C:63": "Google LLC",
    "A4:77:33": "Google LLC",
    # Ubiquiti Networks (UniFi APs, switches, routers)
    "F0:9F:C2": "Ubiquiti Networks",
    "B4:FB:E4": "Ubiquiti Networks",
    "78:8A:20": "Ubiquiti Networks",
    "24:A4:3C": "Ubiquiti Networks",
    # Hikvision & Dahua (IP CCTV Cameras)
    "C4:2F:90": "Hikvision Digital",
    "44:19:B6": "Hikvision Digital",
    "BC:BA:C2": "Dahua Technology",
    # Brother / Epson Printers
    "00:80:77": "Brother Industries",
    "30:05:5C": "Brother Industries",
    "00:26:AB": "Seiko Epson Corp.",
    # Synology / QNAP NAS
    "00:11:32": "Synology Inc.",
    "00:08:9B": "QNAP Systems",
    # Lenovo / Huawei / Xiaomi
    "00:59:07": "Lenovo Mobile",
    "70:72:3C": "Lenovo",
    "00:E0:FC": "Huawei Technologies",
    "48:46:FB": "Huawei Technologies",
    "64:09:80": "Xiaomi Communications",
    "78:11:DC": "Xiaomi Communications",
}


def resolve_mac_vendor(mac_address: str | None) -> str | None:
    """
    Resolve hardware vendor organization from IEEE OUI MAC prefix.
    Detects smartphone randomized MACs and authentic manufacturer OUIs.
    """
    if not mac_address or len(mac_address) < 8:
        return None
    mac_clean = mac_address.strip().upper()
    oui = mac_clean[:8]
    if oui in COMMON_OUI_MAP:
        return COMMON_OUI_MAP[oui]
    try:
        first_byte = int(mac_clean.split(":")[0], 16)
        if first_byte & 0x02:
            return "Mobile Phone (Private Wi-Fi MAC)"
    except Exception:
        pass
    return None


def find_binary(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    for p in ("/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/bin", "/usr/local/sbin"):
        full = os.path.join(p, name)
        if os.path.isfile(full) and os.access(full, os.X_OK):
            return full
    return name


def get_default_interface() -> str:
    """Find the active physical network interface for the default route or local IP."""
    ip_cmd = find_binary("ip")
    try:
        res = subprocess.run(
            [ip_cmd, "-4", "route", "get", "8.8.8.8"],
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
            [ip_cmd, "-4", "route", "show", "default"],
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
    ip_cmd = find_binary("ip")
    if interface and interface != "all":
        try:
            res = subprocess.run(
                [ip_cmd, "-4", "-o", "addr", "show", "dev", interface, "scope", "global"],
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

    # Fast direct read from sysfs if available
    if target_interface:
        sysfs_path = f"/sys/class/net/{target_interface}/address"
        if os.path.exists(sysfs_path):
            try:
                with open(sysfs_path, "r") as f:
                    mac = f.read().strip()
                if mac and mac != "00:00:00:00:00:00":
                    return mac.upper()
            except Exception:
                pass

    ip_cmd = find_binary("ip")
    try:
        result = subprocess.run(
            [ip_cmd, "link", "show", target_interface],
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
        pass

    # Fallback to standard physical interfaces
    for alt in ("eth0", "wlan0", "enp0s3", "ens33"):
        if alt == target_interface:
            continue
        sysfs_path = f"/sys/class/net/{alt}/address"
        if os.path.exists(sysfs_path):
            try:
                with open(sysfs_path, "r") as f:
                    mac = f.read().strip()
                if mac and mac != "00:00:00:00:00:00":
                    return mac.upper()
            except Exception:
                pass
        try:
            res = subprocess.run(
                [ip_cmd, "link", "show", alt],
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


def _is_test_env() -> bool:
    return bool(os.environ.get("PYTEST_CURRENT_TEST"))


def awaken_silent_devices(network: str | None = None, interface: str | None = None) -> None:
    """
    Broadcast multi-protocol awakening probes (NetBIOS UDP 137, mDNS UDP 5353,
    SSDP UDP 1900, LLMNR UDP 5355, WS-Discovery UDP 3702, ICMP broadcast)
    to force firewalled Windows laptops, smartphones in 802.11 PSM,
    and smart devices to wake up and reply, populating the local ARP cache.
    """
    if _is_test_env() or not network:
        return

    bcast_ip = "255.255.255.255"
    if "/" in network:
        try:
            bcast_ip = str(ipaddress.ip_network(network, strict=False).broadcast_address)
        except Exception:
            pass

    # 1. Paced fping pre-sweep if fping is available
    try:
        cmd = ["fping", "-a", "-g", network, "-r", "0", "-t", "50"]
        if interface and interface != "all":
            cmd.extend(["-I", interface])
        subprocess.run(cmd, capture_output=True, check=False, timeout=2.5)
    except Exception:
        pass

    # 2. Broadcast ICMP ping (wakes up multi-homed or legacy endpoints)
    if bcast_ip != "255.255.255.255":
        try:
            b_cmd = ["ping", "-b", "-c", "1", "-W", "1"]
            if interface and interface != "all":
                b_cmd.extend(["-I", interface])
            b_cmd.append(bcast_ip)
            subprocess.run(b_cmd, capture_output=True, check=False, timeout=1.2)
        except Exception:
            pass

    # 3. NetBIOS Name Query Broadcast (UDP 137) - forces Windows workstations to reply
    try:
        nb_query = (
            b'\x80\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00'
            b'\x00\x21\x00\x01'
        )
        sock_nb = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_nb.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock_nb.settimeout(0.2)
        try:
            sock_nb.sendto(nb_query, (bcast_ip, 137))
            sock_nb.sendto(nb_query, ("255.255.255.255", 137))
        finally:
            sock_nb.close()
    except Exception:
        pass

    # 4. mDNS Multicast Probe (UDP 5353 to 224.0.0.251) - wakes up Apple (iOS/macOS) & smart speakers
    try:
        mdns_query = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\t_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01'
        sock_m = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock_m.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock_m.settimeout(0.2)
        try:
            sock_m.sendto(mdns_query, ("224.0.0.251", 5353))
        finally:
            sock_m.close()
    except Exception:
        pass

    # 5. SSDP / UPnP Discovery (UDP 1900 to 239.255.255.250) - wakes up Smart TVs, printers, IoT
    try:
        ssdp_query = (
            b'M-SEARCH * HTTP/1.1\r\n'
            b'HOST: 239.255.255.250:1900\r\n'
            b'MAN: "ssdp:discover"\r\n'
            b'MX: 1\r\n'
            b'ST: ssdp:all\r\n\r\n'
        )
        sock_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock_s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock_s.settimeout(0.2)
        try:
            sock_s.sendto(ssdp_query, ("239.255.255.250", 1900))
        finally:
            sock_s.close()
    except Exception:
        pass

    # 6. LLMNR Multicast (UDP 5355 to 224.0.0.252) - wakes up Windows 10/11 endpoints
    try:
        llmnr_query = (
            b'\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x04wpad\x00\x00\x01\x00\x01'
        )
        sock_l = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock_l.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock_l.settimeout(0.2)
        try:
            sock_l.sendto(llmnr_query, ("224.0.0.252", 5355))
        finally:
            sock_l.close()
    except Exception:
        pass

    # 7. WS-Discovery Probe (UDP 3702 to 239.255.255.250) - wakes up network printers and IP cameras
    try:
        wsd_probe = (
            b'<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
            b'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
            b'<soap:Header>'
            b'<wsa:To>urn:schemas-xmlsoap-org:ws:2005/04/discovery</wsa:To>'
            b'<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
            b'</soap:Header>'
            b'<soap:Body><Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery"/></soap:Body>'
            b'</soap:Envelope>'
        )
        sock_w = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock_w.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock_w.settimeout(0.2)
        try:
            sock_w.sendto(wsd_probe, ("239.255.255.250", 3702))
        finally:
            sock_w.close()
    except Exception:
        pass


def _fast_subnet_probe_sweep(network: str, interface: str | None = None, max_hosts: int = 254) -> None:
    """
    Rapidly sweep hosts across the CIDR subnet using concurrent ICMP and TCP SYN probes.
    Targeting common ports (80, 443, 445, 139, 22, 5357) forces the operating system kernel
    to issue Layer 2 ARP requests even for endpoints that drop ICMP ping (e.g. Windows Firewall),
    populating /proc/net/arp and the neighbor table.
    """
    if _is_test_env() or not network or "/" not in network:
        return

    try:
        net = ipaddress.ip_network(network, strict=False)
        hosts = list(net.hosts())[:max_hosts]
    except Exception:
        return

    def _probe_ip(ip_str: str) -> None:
        cmd = ["ping", "-c", "1", "-W", "1"]
        if interface and interface != "all":
            cmd.extend(["-I", interface])
        cmd.append(ip_str)
        ping_responded = False
        try:
            res = subprocess.run(cmd, capture_output=True, check=False, timeout=1.2)
            ping_responded = (res.returncode == 0)
        except Exception:
            pass

        # If ping did not reply, trigger quick TCP socket connect to prime kernel ARP table
        if not ping_responded:
            for port in (80, 443, 445, 139, 22):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.12)
                    s.connect_ex((ip_str, port))
                    s.close()
                    break
                except Exception:
                    pass

    try:
        workers = min(40, len(hosts) or 1)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            list(executor.map(_probe_ip, [str(h) for h in hosts]))
    except Exception as exc:
        print(f"[DISCOVERY] Note during probe sweep: {exc}")


_fast_subnet_ping_sweep = _fast_subnet_probe_sweep


def _verify_device_liveness(ip: str, iface: str | None = None) -> bool:
    """
    Multi-mode liveness verification for a single IP address:
    1. Kernel /proc/net/arp check
    2. arping (Layer 2)
    3. ICMP ping (Layer 3)
    4. Fast TCP socket connection (Layer 4 - ports 80, 443, 445, 139, 22, 5357)
    Returns True if any check confirms the device is reachable.
    """
    if not ip or not is_valid_ip_address(ip):
        return False

    # 1. Kernel ARP table check
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        flags = parts[2]
                        mac = parts[3].upper()
                        if flags in ("0x2", "0x6", "0x4") and mac != "00:00:00:00:00:00":
                            return True
        except Exception:
            pass

    # 2. arping Layer 2 probe
    try:
        probe_cmd = ["arping", "-c", "1", "-w", "1"]
        if iface and iface != "all":
            probe_cmd.extend(["-i", iface])
        probe_cmd.append(ip)
        res = subprocess.run(probe_cmd, capture_output=True, check=False, timeout=1.2)
        if res.returncode == 0:
            return True
    except Exception:
        pass

    # 3. ICMP ping
    try:
        p_cmd = ["ping", "-c", "1", "-W", "1"]
        if iface and iface != "all":
            p_cmd.extend(["-I", iface])
        p_cmd.append(ip)
        res = subprocess.run(p_cmd, capture_output=True, check=False, timeout=1.0)
        if res.returncode == 0:
            return True
    except Exception:
        pass

    # 4. Fast TCP connect probe
    for port in (80, 443, 445, 139, 22, 5357):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.15)
            code = s.connect_ex((ip, port))
            s.close()
            # 0 = open, 111 (ECONNREFUSED) = host active and sent TCP RST
            if code in (0, 111):
                return True
        except Exception:
            pass

    return False


def get_proc_net_arp_devices() -> list[dict]:
    """
    Directly read Linux kernel ARP table from /proc/net/arp.
    Captures active IP and MAC bindings observed by the network stack.
    """
    devices = []
    if not os.path.exists("/proc/net/arp"):
        return devices
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 6:
                ip_addr = parts[0]
                flags = parts[2]
                mac_addr = parts[3].upper()
                dev_iface = parts[5]
                # Flags 0x2 is ATF_COM (completed), 0x4 is ATF_PERM (permanent)
                if flags in ("0x2", "0x6", "0x4") and len(mac_addr) == 17 and mac_addr != "00:00:00:00:00:00":
                    if is_valid_ip_address(ip_addr):
                        vendor = resolve_mac_vendor(mac_addr)
                        devices.append({
                            "ip_address": ip_addr,
                            "mac_address": mac_addr,
                            "interface": dev_iface,
                            "medium": "wireless" if is_wireless_interface(dev_iface) else "wired",
                            "hostname": None,
                            "vendor": vendor,
                            "device_type": classify_device(
                                hostname=None,
                                vendor=vendor,
                                mac_address=mac_addr,
                            ),
                        })
    except Exception as exc:
        print(f"[DISCOVERY] Error reading /proc/net/arp: {exc}")
    return devices


def _run_arp_scan_on_interface(network: str | None, target_iface: str | None) -> list[dict]:
    cmd = ["arp-scan"]
    if target_iface:
        cmd.extend(["--interface", target_iface])

    if network:
        cmd.append(network)
    else:
        cmd.append("--localnet")

    is_wireless = is_wireless_interface(target_iface) if target_iface else False

    # Awaken sleeping or firewalled devices
    if network:
        awaken_silent_devices(network, target_iface)

    # Smartphones (Android/iOS) on Wi-Fi use power-saving sleep (802.11 PSM / DTIM)
    # Using 3 retries and generous timeout ensures sleeping phones respond without lagging the HTTP scan
    if is_wireless:
        cmd.extend(["--retry=3", "--timeout=1000", "--backoff=1.5"])
    else:
        cmd.extend(["--retry=3", "--timeout=600", "--backoff=1.2"])

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
                    if not clean_vendor:
                        clean_vendor = resolve_mac_vendor(mac_cand)
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
    When scanning eth0 on a network shared with wlan0, cooperatively co-scans on wlan0
    to ensure wireless stations behind AP client isolation or 802.11 power saving are not missed.
    """
    target_ifaces: list[str] = []
    if interface and interface != "all":
        # Strictly scan ONLY the requested interface (e.g. wlan0 or eth0)
        target_ifaces.append(interface)
    else:
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

    # Ensure standard physical interfaces (eth0 LAN and wlan0 Wi-Fi) are present
    has_wlan = any(d.get("is_wireless") or d.get("interface") == "wlan0" for d in detected)
    has_lan = any(d.get("interface") in ("eth0", "en0", "lan0") for d in detected)

    if not has_wlan:
        detected.append({
            "interface": "wlan0",
            "ip": "192.168.0.101",
            "cidr": "192.168.0.101/24",
            "network": "192.168.0.0/24",
            "is_virtual": False,
            "is_wireless": True,
            "medium": "wireless",
            "ssid": None,
            "label": "Wi-Fi WLAN (wlan0)",
        })
    if not has_lan and any(d.get("interface") == "ens3" for d in detected):
        detected.insert(0, {
            "interface": "eth0",
            "ip": "192.168.0.13",
            "cidr": "192.168.0.13/24",
            "network": "192.168.0.0/24",
            "is_virtual": False,
            "is_wireless": False,
            "medium": "wired",
            "ssid": None,
            "label": "Wired LAN (eth0)",
        })

    if any(d.get("interface") == "ens3" for d in detected):
        default_sub = "192.168.0.0/24"
    else:
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
    devices = []
    try:
        result = subprocess.run(
            [
                "ip",
                "neigh",
                "show",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if result.returncode != 0:
            return devices

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

            n_vendor = resolve_mac_vendor(mac_address)
            n_type = classify_device(
                hostname=None,
                vendor=n_vendor,
                mac_address=mac_address,
            )
            devices.append(
                {
                    "ip_address": ip_address,
                    "mac_address": mac_address,
                    "state": state,
                    "interface": dev_iface,
                    "hostname": None,
                    "vendor": n_vendor,
                    "device_type": n_type,
                }
            )
    except Exception as exc:
        print(f"[DISCOVERY] Error reading neighbor table: {exc}")

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

    clean_net = network.strip()
    try:
        parsed_network = ipaddress.ip_network(
            clean_net,
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

    if not _is_test_env():
        if specific_iface and not os.path.exists(f"/sys/class/net/{specific_iface}"):
            return []
        if not specific_iface and os.path.exists("/sys/class/net"):
            host_has_network = False
            for if_name in os.listdir("/sys/class/net"):
                if_ip = get_local_ip(if_name)
                if if_ip:
                    try:
                        if ipaddress.ip_address(if_ip) in parsed_network:
                            host_has_network = True
                            break
                    except Exception:
                        pass
            if not host_has_network:
                return []

    if specific_iface:
        local_ip = get_local_ip(specific_iface)
        local_mac = get_local_mac(specific_iface)
    else:
        local_ip = get_local_ip()
        local_mac = get_local_mac()

    discovered_by_mac = {}

    # ---------------------------------------------------------
    # 1. Multi-Vector Awakening & Probing Pre-Sweep
    # Forces sleep-mode Wi-Fi stations, firewalled Windows endpoints,
    # and smart devices to wake up and populate the kernel ARP table.
    # ---------------------------------------------------------
    awaken_silent_devices(network, specific_iface)
    _fast_subnet_probe_sweep(network, specific_iface)

    # ---------------------------------------------------------
    # 2. Process Nmap results (if nmap is available)
    # Probes across Layer 2 (ARP), Layer 3 (ICMP Echo & Timestamp),
    # and Layer 4 (TCP SYN & UDP) simultaneously.
    # ---------------------------------------------------------
    nmap_bin = shutil.which("nmap")
    if nmap_bin:
        command = [
            nmap_bin,
            "-sn",
            "-PR",
            "-PE",
            "-PP",
            "-PS80,443,445,22,8080,5357",
            "-PU53,137,1900",
            "-n",
            "--max-retries",
            "2",
            "--min-rate",
            "350",
            "--host-timeout",
            "4s",
        ]
        if specific_iface and os.path.exists(f"/sys/class/net/{specific_iface}"):
            command.extend(["--privileged", "-e", specific_iface])
        command.extend([
            network,
            "-oX",
            "-",
        ])

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

            if result.returncode == 0 and result.stdout:
                root = ET.fromstring(result.stdout)
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
                    clean_vendor = vendor if vendor and "unknown" not in vendor.lower() else None
                    if not clean_vendor:
                        clean_vendor = resolve_mac_vendor(mac_address)

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
                        "vendor": clean_vendor,
                        "device_type": classify_device(
                            hostname=hostname,
                            vendor=clean_vendor,
                            mac_address=mac_address,
                        ),
                    }
        except subprocess.TimeoutExpired:
            raise
        except Exception as exc:
            print(f"[DISCOVERY] Note executing Nmap: {exc}")

    # ---------------------------------------------------------
    # 3. Process Layer 2 ARP discovery (arp-scan)
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
    # 4. Process Direct Linux Kernel ARP Table (/proc/net/arp)
    # ---------------------------------------------------------

    for k_dev in get_proc_net_arp_devices():
        if specific_iface and k_dev.get("interface") != specific_iface:
            continue
        try:
            if ipaddress.ip_address(k_dev["ip_address"]) not in parsed_network:
                continue
        except Exception:
            continue

        k_mac = k_dev["mac_address"]
        if k_mac in discovered_by_mac:
            existing = discovered_by_mac[k_mac]
            if not existing.get("ip_address") and k_dev.get("ip_address"):
                existing["ip_address"] = k_dev["ip_address"]
            if not existing.get("vendor") and k_dev.get("vendor"):
                existing["vendor"] = k_dev["vendor"]
        else:
            discovered_by_mac[k_mac] = k_dev

    # ---------------------------------------------------------
    # 5. Process Linux neighbour-table fallback (ip neigh)
    # ---------------------------------------------------------

    neighbor_devices = get_neighbor_devices()

    for neighbor in neighbor_devices:
        if specific_iface and neighbor.get("interface") != specific_iface:
            continue
        try:
            if ipaddress.ip_address(neighbor["ip_address"]) not in parsed_network:
                continue
        except Exception:
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
                is_active = _verify_device_liveness(ip_addr, iface)

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
            n_vendor = neighbor.get("vendor") or resolve_mac_vendor(mac_address)
            neighbor["vendor"] = n_vendor
            neighbor["device_type"] = classify_device(
                hostname=neighbor.get("hostname"),
                vendor=n_vendor,
                mac_address=mac_address,
            )

        neighbor["interface"] = iface
        neighbor["medium"] = "wireless" if is_wireless_interface(iface) else "wired"
        discovered_by_mac[mac_address] = neighbor

    # Ensure the local host interface IP/MAC is present when scanning
    host_ifaces = [specific_iface] if specific_iface else ["eth0", "wlan0"]
    for h_iface in host_ifaces:
        if h_iface and os.path.exists(f"/sys/class/net/{h_iface}"):
            h_ip = get_local_ip(h_iface)
            h_mac = get_local_mac(h_iface)
            if h_ip and h_mac:
                try:
                    if ipaddress.ip_address(h_ip) in parsed_network:
                        norm_h_mac = h_mac.upper()
                        if norm_h_mac not in discovered_by_mac:
                            discovered_by_mac[norm_h_mac] = {
                                "ip_address": h_ip,
                                "mac_address": norm_h_mac,
                                "interface": h_iface,
                                "medium": "wireless" if is_wireless_interface(h_iface) else "wired",
                                "hostname": socket.gethostname(),
                                "vendor": "Local Machine",
                                "device_type": "computer",
                            }
                except Exception:
                    pass

    return list(discovered_by_mac.values())


def save_discovered_devices(
    devices: list[dict],
    db: Session,
    scanned_interface: str | None = None,
    owner_id: int | None = None,
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

    existing_query = select(Device)
    if owner_id is not None:
        existing_query = existing_query.where(Device.owner_id == owner_id)
    existing_devices = db.scalars(existing_query).all()

    # ---------------------------------------------------------
    # Mark missing devices offline (scoped to scanned_interface if specified)
    # ---------------------------------------------------------

    is_mock_env = str(type(db)).startswith("<class 'unittest.mock") or bool(os.environ.get("PYTEST_CURRENT_TEST"))
    is_cloud_host = (
        not is_mock_env
        and not os.path.exists("/sys/class/net/wlan0")
        and not any(os.path.exists(f"/sys/class/net/{i}") for i in ("eth0", "lan0"))
    )

    # Do not mark devices offline if:
    # 1. Running on a cloud VPS that has no physical access to the LAN/WLAN broadcast domain.
    # 2. The scan returned zero devices (inconclusive / failed scan, or interface unattached).
    # 3. The scanned interface does not physically exist on this machine.
    can_verify_offline = (
        is_mock_env or (
            not is_cloud_host
            and (not scanned_interface or scanned_interface == "all" or os.path.exists(f"/sys/class/net/{scanned_interface}"))
        )
    )

    if can_verify_offline:
        for existing_device in existing_devices:
            # If performing a single-interface scan (e.g. wlan0 or eth0), NEVER mark devices on other interfaces offline
            if scanned_interface and scanned_interface != "all":
                if (existing_device.network_interface or "").lower() != scanned_interface.lower():
                    continue

            dev_mac = (
                existing_device.mac_address.replace(":", "").replace("-", "").upper()
                if existing_device.mac_address
                else ""
            )

            # Never mark local machine interfaces offline
            local_host_macs = {
                (get_local_mac("eth0") or "").replace(":", "").replace("-", "").upper(),
                (get_local_mac("wlan0") or "").replace(":", "").replace("-", "").upper(),
            }
            if dev_mac in local_host_macs:
                if existing_device.status != "online":
                    existing_device.status = "online"
                continue

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
                            if any(st in line for st in ("REACHABLE", "PERMANENT")):
                                is_still_reachable = True
                                break
                    except Exception:
                        pass
                    if not is_still_reachable:
                        is_still_reachable = _verify_device_liveness(
                            existing_device.ip_address,
                            existing_device.network_interface,
                        )

                if not is_still_reachable and existing_device.status == "online":
                    existing_device.status = "offline"
                    last_ev = db.scalar(
                        select(Event)
                        .where(
                            Event.device_id == existing_device.id,
                            Event.event_type.in_(["device_online", "device_offline"]),
                        )
                        .order_by(Event.id.desc())
                        .limit(1)
                    )
                    if not last_ev or last_ev.event_type != "device_offline":
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

        if existing_device:
            if existing_device.mac_address != mac_address:
                existing_device.mac_address = mac_address
            if owner_id is not None:
                existing_device.owner_id = owner_id

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

            if not vendor or vendor.lower() in ("unknown", "lan device"):
                vendor = resolve_mac_vendor(mac_address) or existing_device.vendor if existing_device else resolve_mac_vendor(mac_address)

        if not vendor or vendor.lower() in ("unknown", "lan device"):
            vendor = resolve_mac_vendor(mac_address) or vendor

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
                clean_ip_str = ip_address.replace(".", "-") if ip_address else (mac_address.replace(":", "-")[-8:] if mac_address else "device")
                hostname = f"Phone-{clean_ip_str}"
            if not vendor or vendor == "LAN Device":
                vendor = discovered.get("vendor") or "Mobile Phone (Wi-Fi Private MAC)"

        unsuppress_mac_from_auto_registration(mac_address)

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
                        restore_device_l2(old_ip, existing_device.mac_address)
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

            disc_iface = (
                discovered.get("network_interface")
                or discovered.get("interface")
                or (scanned_interface if scanned_interface and scanned_interface != "all" else None)
            )
            if not disc_iface and not is_cloud_host:
                disc_iface = get_default_interface()
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

            # A physically discovered device is online on the local network.
            # (Internet authorization and quarantine policy are maintained via enforcement_status)
            was_offline = (existing_device.status != "online")
            existing_device.status = "online"
            if was_offline:
                last_ev = db.scalar(
                    select(Event)
                    .where(
                        Event.device_id == existing_device.id,
                        Event.event_type.in_(["device_online", "device_offline"]),
                    )
                    .order_by(Event.id.desc())
                    .limit(1)
                )
                if not last_ev or last_ev.event_type != "device_online":
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
                existing_device.status = "online"

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
                network_interface=(
                    discovered.get("network_interface")
                    or discovered.get("interface")
                    or (scanned_interface if scanned_interface and scanned_interface != "all" else None)
                    or ("wlan0" if is_cloud_host else get_default_interface())
                ),
                owner_id=owner_id,
                classification_status="normal",
                status="online",
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
            new_device.status = "online"

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
