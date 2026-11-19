import os

COMMON_OUI_MAP: dict[str, str] = {
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
    # VoIP Phones (Yealink, Polycom, Grandstream, Snom, Fanvil, Cisco VoIP)
    "80:5E:C0": "Yealink Network Technology",
    "44:DB:D2": "Yealink Network Technology",
    "80:5E:0C": "Yealink Network Technology",
    "24:9A:D8": "Yealink Network Technology",
    "00:15:65": "Yealink Network Technology",
    "64:16:7F": "Polycom",
    "00:04:F2": "Polycom",
    "00:0B:82": "Grandstream Networks",
    "00:04:13": "SNOM Technology",
    "0C:38:3E": "Fanvil Technology",
    # Mobile Phone Vendors (Transsion, Oppo, Vivo, OnePlus, Realme)
    "70:12:F0": "Transsion Holdings (Infinix/Tecno)",
    "F4:60:E2": "Transsion Holdings (Infinix/Tecno)",
    "38:71:DE": "Transsion Holdings (Infinix/Tecno)",
    "E8:65:D4": "OnePlus Technology",
    "94:08:53": "Guangdong OPPO Mobile",
    "2C:5B:B8": "vivo Mobile Communication",
}

_SYSTEM_OUI_CACHE: dict[str, str] = {}
_SYSTEM_OUI_LOADED: bool = False


def _ensure_system_oui_loaded() -> None:
    global _SYSTEM_OUI_LOADED
    if _SYSTEM_OUI_LOADED:
        return
    _SYSTEM_OUI_LOADED = True

    candidate_paths = [
        "/usr/share/nmap/nmap-mac-prefixes",
        "/usr/share/arp-scan/ieee-oui.txt",
        "/usr/share/ieee-data/oui.txt",
        "/var/lib/ieee-data/oui.txt",
    ]

    for path in candidate_paths:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(maxsplit=1)
                    if len(parts) == 2:
                        raw_prefix = parts[0].replace(":", "").replace("-", "").upper()
                        if len(raw_prefix) == 6:
                            norm_prefix = f"{raw_prefix[:2]}:{raw_prefix[2:4]}:{raw_prefix[4:6]}"
                            if norm_prefix not in _SYSTEM_OUI_CACHE:
                                _SYSTEM_OUI_CACHE[norm_prefix] = parts[1].strip()
        except Exception:
            pass


def is_private_mac(mac_address: str | None) -> bool:
    """Return True if MAC address has IEEE 802 Locally Administered bit set (Private/Randomized Wi-Fi MAC)."""
    if not mac_address or len(mac_address) < 8:
        return False
    mac_clean = mac_address.strip().upper()
    # Exclude simulated test prefixes and known virtualization MACs
    if any(mac_clean.startswith(prefix) for prefix in ("02:AA:BB", "AA:BB:CC", "52:54:00", "00:16:3E", "00:50:56")):
        return False
    try:
        first_byte = int(mac_clean.split(":")[0], 16)
        if (first_byte & 0x02) != 0:
            return True
    except Exception:
        pass
    return False


def resolve_mac_vendor(mac_address: str | None) -> str | None:
    """
    Resolve hardware vendor organization from IEEE OUI MAC prefix.
    Checks common map, system IEEE database (40,000+ vendors), and smartphone Private MACs.
    """
    if not mac_address or len(mac_address) < 8:
        return None

    mac_clean = mac_address.strip().upper()
    oui = mac_clean[:8]

    if oui in COMMON_OUI_MAP:
        return COMMON_OUI_MAP[oui]

    _ensure_system_oui_loaded()
    if oui in _SYSTEM_OUI_CACHE:
        return _SYSTEM_OUI_CACHE[oui]

    # Check for private/randomized Wi-Fi MAC on mobile phones
    if is_private_mac(mac_clean):
        return "Mobile Phone (Private Wi-Fi MAC)"

    return None
