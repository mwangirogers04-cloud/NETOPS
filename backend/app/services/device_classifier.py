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
        2. CCTV / surveillance
        3. Printer
        4. Computer
        5. Known MAC/OUI rule
        6. Unknown

    Returns:
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
