from .mac_vendor import is_private_mac, resolve_mac_vendor


def classify_device(
    hostname: str | None = None,
    vendor: str | None = None,
    mac_address: str | None = None,
    network_interface: str | None = None,
    medium: str | None = None,
    current_type: str | None = None,
) -> str:
    """
    Thoroughly classify a network device using vendor OUI, hostname,
    MAC address, network medium, and existing classification context.

    Classification order:
        1. Explicit current classification preservation (phones, VoIP)
        2. Hostname explicit phone identification
        3. Local machine
        4. IP Phones / VoIP Telephony
        5. Mobile Phones / Smartphones (Transsion, Samsung, Apple iOS, Xiaomi, etc.)
        6. Access Points / Wi-Fi & Network Infrastructure
        7. Servers / Datacenter Infrastructure
        8. CCTV / Surveillance
        9. Printers
        10. Computers / Laptops / Workstations
        11. Private/Randomized MAC Fallback
        12. Unknown

    Returns:
        ip_phone, phone, server, access_point, computer, cctv, printer, unknown
    """

    # If vendor is missing or generic, attempt full IEEE OUI resolution from MAC
    if (not vendor or vendor.strip().lower() in ("generic", "lan device", "unknown", "")) and mac_address:
        resolved = resolve_mac_vendor(mac_address)
        if resolved:
            vendor = resolved

    hostname_text = (hostname or "").lower().strip()
    vendor_text = (vendor or "").lower().strip()
    mac_text = (mac_address or "").upper().strip()

    text = f"{hostname_text} {vendor_text}"

    # ---------------------------------------------------------
    # 1. Respect Existing Explicit Phone Classification
    # ---------------------------------------------------------
    if current_type and current_type.lower().strip() in ("ip_phone", "phone", "voip", "smartphone", "mobile"):
        # Unless the vendor/hostname unambiguously proves it is a physical switch/server/printer
        infra_clues = ("cisco switch", "poweredge", "proliant", "esxi", "laserjet", "hikvision")
        if not any(clue in text for clue in infra_clues):
            return "phone" if current_type.lower().strip() == "phone" else "ip_phone"

    # ---------------------------------------------------------
    # 2. Hostname Explicitly Identifies as Phone
    # ---------------------------------------------------------
    explicit_phone_host_prefixes = (
        "phone-", "phone_", "iphone", "ipad", "android", "galaxy", "pixel",
        "redmi", "tecno", "infinix", "oppo", "vivo", "oneplus", "realme"
    )
    if any(hostname_text.startswith(p) for p in explicit_phone_host_prefixes):
        return "phone"

    # ---------------------------------------------------------
    # 3. Local Machine
    # ---------------------------------------------------------
    local_machine_keywords = [
        "local machine",
        "localhost",
    ]
    if any(keyword in text for keyword in local_machine_keywords):
        return "computer"

    # ---------------------------------------------------------
    # 4. IP Phones / VoIP Telephony Hardware (VLAN 10)
    # ---------------------------------------------------------
    phone_keywords = [
        "ip phone",
        "ipphone",
        "voip",
        "sip phone",
        "telephone",
        "polycom",
        "poly inc",
        "poly com",
        "yealink",
        "grandstream",
        "snom",
        "fanvil",
        "cisco ip phone",
        "avaya",
        "mitel",
        "gigaset",
        "audiocodes",
        "htek",
        "digium",
        "sangoma",
        "algo communication",
        "cyberdata",
        "spectralink",
    ]
    if any(keyword in text for keyword in phone_keywords):
        return "ip_phone"

    # Cisco IP Phones often have vendor 'Cisco Systems' with CP/SPA/79xx/88xx in model/hostname
    if "cisco" in vendor_text and any(m in hostname_text for m in ("cp-", "spa", "7940", "7960", "8841", "8851", "8861", "6921")):
        return "ip_phone"

    # ---------------------------------------------------------
    # 5. Mobile Phones / Smartphones (VLAN 10)
    # ---------------------------------------------------------
    mobile_vendors_and_keywords = [
        "phone",
        "smartphone",
        "mobile",
        "android",
        "iphone",
        "ipad",
        "ipod",
        "galaxy",
        "samsung",
        "pixel",
        "xiaomi",
        "redmi",
        "poco",
        "transsion",
        "infinix",
        "tecno",
        "itel",
        "oppo",
        "vivo",
        "oneplus",
        "realme",
        "meizu",
        "honor",
        "huawei mobile",
        "motorola mobility",
        "motorola",
        "moto ",
        "hmd global",
        "zte",
        "nubia",
        "nothing technology",
        "nothing phone",
        "blackview",
        "ulefone",
        "doogee",
        "oukitel",
        "umidigi",
        "sony mobile",
        "xperia",
    ]
    if any(keyword in text for keyword in mobile_vendors_and_keywords):
        return "phone"

    # Apple Devices Differentiation (iPhone/iPad vs Mac):
    # If vendor is Apple, distinguish mobile devices from Mac desktops/laptops
    if "apple" in vendor_text:
        mac_pc_clues = ("macbook", "imac", "mac mini", "macmini", "mac pro", "macpro", "mac studio", "macos", "os x", "darwin")
        if any(clue in hostname_text for clue in mac_pc_clues):
            return "computer"
        # Overwhelming majority of Apple endpoints on Wi-Fi are iPhones/iPads
        return "phone"

    # Locally Administered / Private Wi-Fi MACs used by modern iOS and Android smartphones
    if is_private_mac(mac_text):
        is_wireless = bool(
            (medium and medium.lower() == "wireless")
            or (network_interface and network_interface.startswith(("wlan", "wl")))
            or "private wi-fi" in vendor_text
            or not vendor_text
            or vendor_text in ("lan device", "unknown")
        )
        if is_wireless:
            return "phone"

    # ---------------------------------------------------------
    # 6. Access Points / Wireless & Network Infrastructure
    # ---------------------------------------------------------
    ap_keywords = [
        "access point",
        "accesspoint",
        "unifi",
        "ubiquiti",
        "uap",
        "aerohive",
        "ruckus",
        "aruba ap",
        "aruba",
        "meraki mr",
        "meraki",
        "tp-link omada",
        "tp-link",
        "tplink",
        "tenda",
        "routerboard",
        "mikrotik",
        "netgear",
        "d-link",
        "linksys",
        "cisco ap",
        "eap",
        "wap",
        "wireless ap",
    ]
    if any(keyword in text for keyword in ap_keywords):
        return "access_point"

    # ---------------------------------------------------------
    # 7. Servers / Datacenter Infrastructure
    # ---------------------------------------------------------
    server_keywords = [
        "server",
        "srv-",
        "srv.",
        "esxi",
        "proxmox",
        "hyper-v",
        "truenas",
        "freenas",
        "synology",
        "qnap",
        "poweredge",
        "proliant",
        "supermicro",
        "domain controller",
        "datacenter",
        "nas",
        "sophos",
        "fortinet",
        "palo alto",
        "pfsense",
        "opnsense",
        "firewall",
        "gateway",
        "cisco switch",
    ]
    if any(keyword in text for keyword in server_keywords):
        return "server"

    # ---------------------------------------------------------
    # 8. CCTV / Surveillance
    # ---------------------------------------------------------
    cctv_keywords = [
        "hikvision",
        "dahua",
        "axis communications",
        "axis ",
        "hanwha",
        "uniview",
        "camera",
        "cctv",
        "surveillance",
        "nvr",
        "dvr",
        "ipcam",
        "ip camera",
    ]
    if any(keyword in text for keyword in cctv_keywords):
        return "cctv"

    # ---------------------------------------------------------
    # 9. Printers
    # ---------------------------------------------------------
    printer_keywords = [
        "printer",
        "print",
        "laserjet",
        "deskjet",
        "officejet",
        "hewlett-packard",
        "hp inc",
        "canon",
        "epson",
        "brother",
        "lexmark",
        "xerox",
        "ricoh",
        "kyocera",
        "konica minolta",
    ]
    if any(keyword in text for keyword in printer_keywords):
        return "printer"

    # ---------------------------------------------------------
    # 10. Computers / Laptops / Workstations
    # ---------------------------------------------------------
    computer_keywords = [
        "windows",
        "microsoft",
        "desktop",
        "laptop",
        "computer",
        "pc",
        "ubuntu",
        "debian",
        "linux",
        "fedora",
        "centos",
        "red hat",
        "dell",
        "lenovo",
        "asus",
        "acer",
        "macbook",
        "imac",
        "mac mini",
        "macmini",
        "mac pro",
        "macpro",
        "intel",
        "amd",
        "thinkpad",
        "workstation",
        "latitude",
        "optiplex",
        "inspiron",
        "surface",
        "toshiba",
        "sony vaio",
    ]
    if any(keyword in text for keyword in computer_keywords):
        return "computer"

    # ---------------------------------------------------------
    # 11. Known MAC/OUI Fallback
    # ---------------------------------------------------------
    known_mac_prefixes = {
        # Verified explicit OUI mappings can be placed here if needed
    }
    mac_prefix = mac_text[:8]
    if mac_prefix in known_mac_prefixes:
        return known_mac_prefixes[mac_prefix]

    # ---------------------------------------------------------
    # 12. Unknown
    # ---------------------------------------------------------
    return "unknown"
