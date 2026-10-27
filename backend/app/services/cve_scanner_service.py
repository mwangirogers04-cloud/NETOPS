"""
Device Firmware & OS CVE Vulnerability Scanner Service
=====================================================
Analyzes network endpoints, operating systems, hardware models, and network services
against an industry-aligned CVE knowledge base (NIST NVD / MITRE).
Assigns CVSS v3.1 scores, risk severities, exploitability flags, and remediation steps.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..models.device import Device
from ..models.device_vulnerability import DeviceVulnerability
from ..models.endpoint_update import EndpointUpdate
from ..services.event_service import create_event

logger = logging.getLogger("netops.cve_scanner")

# Curated Industry CVE Knowledge Base
CVE_CATALOG: list[dict[str, Any]] = [
    # Linux & OpenSSH
    {
        "cve_id": "CVE-2024-6387",
        "title": "regreSSHion: Remote Unauthenticated Root Code Execution in OpenSSH",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_component": "OpenSSH Server (sshd)",
        "description": "Signal handler race condition in OpenSSH's server daemon (sshd) enables unauthenticated remote code execution with root privileges on glibc-based Linux systems.",
        "remediation": "Upgrade OpenSSH to version 9.8p1 or newer immediately. Alternatively, set LoginGraceTime 0 in /etc/ssh/sshd_config as temporary mitigation.",
        "exploit_available": True,
        "match_keywords": ["linux", "ubuntu", "debian", "centos", "rhel", "ssh", "server"],
    },
    {
        "cve_id": "CVE-2024-1086",
        "title": "Linux Kernel Netfilter nf_tables Use-After-Free Local Privilege Escalation",
        "cvss_score": 7.8,
        "severity": "HIGH",
        "affected_component": "Linux Kernel (nf_tables)",
        "description": "A use-after-free vulnerability in the netfilter nf_tables subsystem allows unprivileged local users to achieve arbitrary kernel memory write and root escalation.",
        "remediation": "Apply the latest vendor kernel updates (Linux kernel >= 6.8.4 or distro backport). Restrict user unprivileged namespace creation.",
        "exploit_available": True,
        "match_keywords": ["linux", "ubuntu", "debian", "kernel"],
    },
    {
        "cve_id": "CVE-2023-4911",
        "title": "Looney Tunables: GNU C Library ld.so Dynamic Loader Buffer Overflow",
        "cvss_score": 7.8,
        "severity": "HIGH",
        "affected_component": "glibc ld.so",
        "description": "Buffer overflow in the GNU C Library's dynamic loader handling of the GLIBC_TUNABLES environment variable leads to local root privilege escalation.",
        "remediation": "Update glibc and libc6 packages to patched versions via package manager.",
        "exploit_available": True,
        "match_keywords": ["linux", "ubuntu", "debian", "centos", "redhat", "glibc"],
    },
    # Windows
    {
        "cve_id": "CVE-2024-38063",
        "title": "Windows TCP/IP Remote Code Execution Vulnerability (Zero-Click)",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_component": "Windows TCP/IP Stack (tcpip.sys)",
        "description": "Integer underflow flaw in the Windows TCP/IP networking stack processing IPv6 packets enables unauthenticated remote attackers to execute arbitrary code via specially crafted IPv6 packets.",
        "remediation": "Apply Microsoft Security Update KB5041585 or disable IPv6 on the network adapter if patching is delayed.",
        "exploit_available": True,
        "match_keywords": ["windows", "win10", "win11", "desktop", "workstation", "microsoft"],
    },
    {
        "cve_id": "CVE-2023-36884",
        "title": "Microsoft Windows Office & HTML Remote Code Execution",
        "cvss_score": 8.3,
        "severity": "HIGH",
        "affected_component": "Windows Search & HTML Engine",
        "description": "Attackers can craft malicious Microsoft Office documents that execute arbitrary code using crafted file extensions and web links.",
        "remediation": "Install the Microsoft Defense-in-Depth cumulative update and enable Microsoft Defender Attack Surface Reduction (ASR) rules.",
        "exploit_available": True,
        "match_keywords": ["windows", "win10", "win11", "office"],
    },
    # Apple macOS & iOS
    {
        "cve_id": "CVE-2024-27834",
        "title": "Apple macOS & iOS Kernel Memory Pointer Authentication Bypass",
        "cvss_score": 8.8,
        "severity": "HIGH",
        "affected_component": "XNU Kernel",
        "description": "An issue in pointer authentication bypass in the XNU Kernel allows an attacker with arbitrary read/write capability to bypass Kernel PAC and run arbitrary kernel-level payloads.",
        "remediation": "Update to macOS Sonoma 14.5, iOS 17.5, or newer versions.",
        "exploit_available": True,
        "match_keywords": ["apple", "mac", "macos", "ios", "iphone", "ipad"],
    },
    # Cisco Switches & Routers
    {
        "cve_id": "CVE-2023-20198",
        "title": "Cisco IOS XE Web UI Unauthenticated Privilege Escalation",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "affected_component": "Cisco IOS XE Web Management Service",
        "description": "Vulnerability in the web UI feature of Cisco IOS XE software allows an unauthenticated, remote attacker to create an account with privilege level 15 access.",
        "remediation": "Disable the Cisco IOS XE Web UI HTTP/HTTPS server using 'no ip http server' and 'no ip http secure-server' and apply the latest Cisco patch.",
        "exploit_available": True,
        "match_keywords": ["cisco", "catalyst", "switch", "router", "ios"],
    },
    # Sophos Firewalls
    {
        "cve_id": "CVE-2022-3236",
        "title": "Sophos Firewall User Portal & Webadmin Remote Code Execution",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_component": "Sophos SFOS User Portal & Webadmin",
        "description": "A code injection vulnerability in the User Portal and Webadmin of Sophos Firewall allows unauthenticated remote code execution.",
        "remediation": "Update Sophos Firewall firmware to v19.5 MR-1, v19.0 MR-1, or v18.5 MR-5. Disable WAN access to the User Portal and Webadmin.",
        "exploit_available": True,
        "match_keywords": ["sophos", "firewall", "sfos", "xg"],
    },
    # Fortinet FortiGate
    {
        "cve_id": "CVE-2024-21762",
        "title": "Fortinet FortiOS SSL-VPN Out-of-Bounds Write Remote Code Execution",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_component": "FortiOS SSL-VPN Daemon",
        "description": "An out-of-bounds write vulnerability in FortiOS allows a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted HTTP requests.",
        "remediation": "Upgrade FortiOS to version 7.4.3, 7.2.7, 7.0.14, or disable SSL-VPN on internet-facing interfaces.",
        "exploit_available": True,
        "match_keywords": ["fortinet", "fortigate", "fortios", "firewall"],
    },
    # MikroTik RouterOS
    {
        "cve_id": "CVE-2023-32154",
        "title": "MikroTik RouterOS IPv6 Advertisement Buffer Overflow",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_component": "RouterOS IPv6 Daemon",
        "description": "A buffer overflow flaw in the IPv6 route advertisement parsing in MikroTik RouterOS allows attackers on the adjacent network to execute arbitrary code with admin privileges.",
        "remediation": "Upgrade RouterOS to version >= 7.9.1 or disable IPv6 if not in active production use.",
        "exploit_available": True,
        "match_keywords": ["mikrotik", "routeros", "router"],
    },
    # IP Cameras & CCTV IoT
    {
        "cve_id": "CVE-2021-36260",
        "title": "Hikvision IP Camera Unauthenticated Remote Command Injection",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_component": "Hikvision Web Server",
        "description": "Insufficient input validation in the web server of Hikvision cameras allows unauthenticated remote attackers to send crafted packets and gain full root shell access.",
        "remediation": "Update camera firmware to the latest manufacturer release. Isolate surveillance devices strictly to Quarantine/CCTV VLAN 30/90.",
        "exploit_available": True,
        "match_keywords": ["camera", "cctv", "hikvision", "surveillance", "dahua", "axis", "nvr"],
    },
    # VoIP Phones
    {
        "cve_id": "CVE-2021-1400",
        "title": "Cisco & Polycom Enterprise IP Phone Remote Code Execution",
        "cvss_score": 8.8,
        "severity": "HIGH",
        "affected_component": "VoIP SIP / CDP Daemon",
        "description": "Flaw in Cisco Discovery Protocol and SIP packet parser enables adjacent attackers to reload the device or execute arbitrary code with elevated privileges.",
        "remediation": "Update VoIP phone firmware and place phones strictly into Voice VLAN 10 with 802.1p CoS prioritization.",
        "exploit_available": True,
        "match_keywords": ["voip", "phone", "sip", "polycom", "yealink", "ip phone"],
    },
    # Network Printers
    {
        "cve_id": "CVE-2022-3942",
        "title": "HP Enterprise LaserJet & OfficeJet Buffer Overflow RCE",
        "cvss_score": 8.4,
        "severity": "HIGH",
        "affected_component": "Printer Network Link-Local Daemon",
        "description": "Buffer overflow in the link-local daemon of HP enterprise printers allows unauthenticated network users to execute code or cause a permanent denial of service.",
        "remediation": "Apply the latest HP FutureSmart firmware update. Disable LLMNR and Telnet on the printer management page.",
        "exploit_available": True,
        "match_keywords": ["printer", "laserjet", "hp", "canon", "epson", "xerox", "mfp"],
    },
]


def evaluate_device_vulnerabilities(
    device: Device,
    endpoint_update: EndpointUpdate | None = None,
) -> list[dict[str, Any]]:
    """
    Match device characteristics against the CVE catalog using vendor,
    device type, hostname, and OS metadata.
    """
    matched: list[dict[str, Any]] = []

    # Gather search corpus
    corpus_parts = [
        device.hostname or "",
        device.vendor or "",
        device.device_type or "",
        device.notes or "",
    ]
    if endpoint_update:
        corpus_parts.extend([
            endpoint_update.operating_system or "",
            endpoint_update.os_version or "",
            endpoint_update.architecture or "",
        ])

    corpus = " ".join(corpus_parts).lower()

    for item in CVE_CATALOG:
        keywords = item.get("match_keywords", [])
        # Match if any keyword appears in the corpus
        matches = [kw for kw in keywords if kw in corpus]
        if matches:
            matched.append({
                "cve_id": item["cve_id"],
                "title": item["title"],
                "cvss_score": item["cvss_score"],
                "severity": item["severity"],
                "affected_component": item["affected_component"],
                "description": item["description"],
                "remediation": item["remediation"],
                "exploit_available": item["exploit_available"],
                "matched_on": matches,
            })

    # Sort descending by CVSS score
    matched.sort(key=lambda x: x["cvss_score"], reverse=True)
    return matched


def scan_device_for_cves(db: Session, device_id: int) -> dict[str, Any]:
    """
    Execute vulnerability assessment on a device, persist findings in the database,
    and return detailed CVSS risk posture.
    """
    device = db.get(Device, device_id)
    if not device:
        raise ValueError(f"Device #{device_id} not found.")

    # Find matching endpoint update info if available
    endpoint_update = db.scalar(
        select(EndpointUpdate)
        .where(
            (EndpointUpdate.mac_address == device.mac_address)
            | (EndpointUpdate.ip_address == device.ip_address)
        )
        .order_by(EndpointUpdate.last_checked.desc())
        .limit(1)
    )

    findings = evaluate_device_vulnerabilities(device, endpoint_update)

    # Clear previous vulnerability records for this device
    db.execute(delete(DeviceVulnerability).where(DeviceVulnerability.device_id == device.id))

    # Insert new vulnerability records
    for f in findings:
        vuln = DeviceVulnerability(
            device_id=device.id,
            cve_id=f["cve_id"],
            severity=f["severity"],
            cvss_score=f["cvss_score"],
            title=f["title"],
            description=f["description"],
            affected_component=f["affected_component"],
            remediation=f["remediation"],
            exploit_available=f["exploit_available"],
        )
        db.add(vuln)

    db.commit()

    # Calculate overall risk posture
    max_score = max([f["cvss_score"] for f in findings], default=0.0)
    if max_score >= 9.0:
        overall_risk = "CRITICAL"
    elif max_score >= 7.0:
        overall_risk = "HIGH"
    elif max_score >= 4.0:
        overall_risk = "MEDIUM"
    elif max_score > 0.0:
        overall_risk = "LOW"
    else:
        overall_risk = "CLEAN"

    if overall_risk in ("CRITICAL", "HIGH") and device.approval_status == "approved":
        create_event(
            db=db,
            event_type="vulnerability_detected",
            message=(
                f"CVE Vulnerability Alert: Device {device.hostname or device.ip_address} ({device.mac_address}) "
                f"has {len(findings)} vulnerability/ies (Max CVSS: {max_score:.1f} {overall_risk}). "
                f"Top CVE: {findings[0]['cve_id']} - {findings[0]['title']}."
            ),
            device_id=device.id,
            actor="cve_scanner",
        )
        db.commit()

    return {
        "device_id": device.id,
        "hostname": device.hostname or "Unknown Endpoint",
        "mac_address": device.mac_address,
        "ip_address": device.ip_address,
        "device_type": device.device_type,
        "vendor": device.vendor,
        "overall_risk": overall_risk,
        "max_cvss_score": max_score,
        "vulnerabilities_count": len(findings),
        "vulnerabilities": findings,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


def scan_all_devices_for_cves(db: Session) -> dict[str, Any]:
    """Execute CVE vulnerability assessment across the entire network inventory."""
    devices = list(db.scalars(select(Device)).all())
    results = []

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}

    for dev in devices:
        res = scan_device_for_cves(db, dev.id)
        risk = res["overall_risk"]
        counts[risk] = counts.get(risk, 0) + 1
        results.append(res)

    return {
        "total_devices_scanned": len(devices),
        "risk_breakdown": counts,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "devices": results,
    }


def get_device_vulnerabilities(db: Session, device_id: int) -> dict[str, Any]:
    """Retrieve existing stored vulnerability records or execute a fresh scan."""
    device = db.get(Device, device_id)
    if not device:
        raise ValueError(f"Device #{device_id} not found.")

    stored = list(
        db.scalars(
            select(DeviceVulnerability)
            .where(DeviceVulnerability.device_id == device_id)
            .order_by(DeviceVulnerability.cvss_score.desc())
        ).all()
    )

    if not stored:
        return scan_device_for_cves(db, device_id)

    max_score = max([v.cvss_score for v in stored], default=0.0)
    if max_score >= 9.0:
        overall_risk = "CRITICAL"
    elif max_score >= 7.0:
        overall_risk = "HIGH"
    elif max_score >= 4.0:
        overall_risk = "MEDIUM"
    elif max_score > 0.0:
        overall_risk = "LOW"
    else:
        overall_risk = "CLEAN"

    return {
        "device_id": device.id,
        "hostname": device.hostname or "Unknown Endpoint",
        "mac_address": device.mac_address,
        "ip_address": device.ip_address,
        "device_type": device.device_type,
        "vendor": device.vendor,
        "overall_risk": overall_risk,
        "max_cvss_score": max_score,
        "vulnerabilities_count": len(stored),
        "vulnerabilities": [
            {
                "cve_id": v.cve_id,
                "title": v.title,
                "cvss_score": v.cvss_score,
                "severity": v.severity,
                "affected_component": v.affected_component,
                "description": v.description,
                "remediation": v.remediation,
                "exploit_available": v.exploit_available,
                "scanned_at": v.scanned_at.isoformat() if v.scanned_at else None,
            }
            for v in stored
        ],
        "scanned_at": stored[0].scanned_at.isoformat() if stored and stored[0].scanned_at else datetime.now(timezone.utc).isoformat(),
    }
