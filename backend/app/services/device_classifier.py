def classify_device(
    hostname: str | None = None,
    vendor: str | None = None,
    mac_address: str | None = None,
) -> str:
    """
    Classify a network device using hostname, vendor,
    and MAC address information.

    Classification order:
        1. Local machine
        2. IP Phones / VoIP
        3. Access Points / Wi-Fi
        4. Servers / Infrastructure
        5. CCTV / surveillance
        6. Printer
        7. Computer
        8. Known MAC/OUI rule
        9. Unknown

    Returns:
        ip_phone
        server
        access_point
        computer
        cctv
        printer
        unknown
    """

    hostname_text = (hostname or "").lower().strip()
    vendor_text = (vendor or "").lower().strip()
    mac_text = (mac_address or "").upper().strip()

    text = f"{hostname_text} {vendor_text}"

    # ---------------------------------------------------------
    # Local Machine
    # ---------------------------------------------------------

    local_machine_keywords = [
        "local machine",
        "localhost",
    ]

    if any(keyword in text for keyword in local_machine_keywords):
        return "computer"

    # ---------------------------------------------------------
    # IP Phones / VoIP Telephony
    # ---------------------------------------------------------

    phone_keywords = [
        "ip phone",
        "ipphone",
        "voip",
        "sip phone",
        "telephone",
        "polycom",
        "poly",
        "yealink",
        "grandstream",
        "snom",
        "fanvil",
        "cisco ip phone",
        "avaya",
        "mitel",
        "gigaset",
        "audiocodes",
    ]

    if any(keyword in text for keyword in phone_keywords):
        return "ip_phone"

    # ---------------------------------------------------------
    # Access Points / Wireless Infrastructure
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
        "meraki mr",
        "tp-link omada",
        "eap",
        "wap",
        "wireless ap",
    ]

    if any(keyword in text for keyword in ap_keywords):
        return "access_point"

    # ---------------------------------------------------------
    # Servers / Datacenter Infrastructure
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
    ]

    if any(keyword in text for keyword in server_keywords):
        return "server"

    # ---------------------------------------------------------
    # CCTV / Surveillance
    # ---------------------------------------------------------

    cctv_keywords = [
        "hikvision",
        "dahua",
        "axis communications",
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
    # Printers
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
    # Computers
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
        "apple",
        "macbook",
        "imac",
        "intel",
        "amd",
    ]

    if any(keyword in text for keyword in computer_keywords):
        return "computer"

    # ---------------------------------------------------------
    # Known MAC/OUI Rules
    # ---------------------------------------------------------
    #
    # Only verified OUI rules should be placed here.
    #
    # Simulated prefixes such as AA:BB:CC are intentionally
    # excluded.
    # ---------------------------------------------------------

    known_mac_prefixes = {
        # Example:
        # "XX:XX:XX": "computer",
    }

    mac_prefix = mac_text[:8]

    if mac_prefix in known_mac_prefixes:
        return known_mac_prefixes[mac_prefix]

    # ---------------------------------------------------------
    # Unknown
    # ---------------------------------------------------------

    return "unknown"
