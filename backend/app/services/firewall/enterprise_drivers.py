import base64
import json
import logging
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any
from urllib.parse import urlparse

from .base import BaseFirewallDriver

logger = logging.getLogger(__name__)


class GenericEnterpriseRESTFirewallDriver(BaseFirewallDriver):
    """
    Base REST/HTTPS driver for Enterprise Next-Generation Firewalls (Palo Alto PAN-OS,
    Check Point Quantum, Juniper SRX, SonicWall SonicOS, WatchGuard Fireware,
    Ubiquiti UniFi/EdgeOS, ArubaOS Gateway, Huawei USG).
    """

    status_endpoint: str = "/api/v1/status"
    block_endpoint: str = "/api/v1/quarantine/block"
    allow_endpoint: str = "/api/v1/quarantine/allow"
    firmware_label: str = "Enterprise NGFW"

    def is_configured(self) -> bool:
        return bool(self.management_url and (self.api_key or (self.username and self.password)))

    def _build_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
            headers["X-API-Key"] = self.api_key
        elif self.username and self.password:
            creds = f"{self.username}:{self.password}".encode("utf-8")
            b64 = base64.b64encode(creds).decode("ascii")
            headers["Authorization"] = f"Basic {b64}"
        return headers

    def _request(
        self,
        path: str,
        method: str = "GET",
        payload: dict | None = None,
        timeout: float = 6.0,
    ) -> dict[str, Any]:
        url = f"{self.management_url.rstrip('/')}{path}"
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(url, data=data, headers=self._build_headers(), method=method)

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                try:
                    return json.loads(raw)
                except Exception:
                    return {"raw": raw, "status_code": resp.status}
        except urllib.error.HTTPError as exc:
            return {"http_error": exc.code, "reason": exc.reason}
        except Exception as exc:
            logger.error(f"{self.vendor_title} API request to {url} failed: {exc}")
            raise RuntimeError(f"{self.vendor_title} communication failure: {exc}") from exc

    def test_connection(self) -> dict[str, Any]:
        if not self.is_configured():
            return {
                "connected": False,
                "vendor": self.vendor,
                "vendor_title": self.vendor_title,
                "firewall_ip": None,
                "api_version": None,
                "quarantine_rule_active": False,
                "quarantined_hosts_count": 0,
                "error": f"{self.vendor_title} is not configured (missing management URL or credentials/API key)",
            }

        parsed = urlparse(self.management_url)
        firewall_ip = parsed.hostname or self.management_url

        try:
            res = self._request(self.status_endpoint)
            if "http_error" in res:
                return {
                    "connected": False,
                    "vendor": self.vendor,
                    "vendor_title": self.vendor_title,
                    "firewall_ip": firewall_ip,
                    "api_version": None,
                    "quarantine_rule_active": False,
                    "quarantined_hosts_count": 0,
                    "error": f"HTTP {res['http_error']}: {res.get('reason')}",
                }
            return {
                "connected": True,
                "vendor": self.vendor,
                "vendor_title": self.vendor_title,
                "firewall_ip": firewall_ip,
                "api_version": str(res.get("version") or self.firmware_label),
                "quarantine_rule_active": True,
                "quarantined_hosts_count": int(res.get("quarantined_count", 0)),
                "error": None,
            }
        except Exception as exc:
            return {
                "connected": False,
                "vendor": self.vendor,
                "vendor_title": self.vendor_title,
                "firewall_ip": firewall_ip,
                "api_version": None,
                "quarantine_rule_active": False,
                "quarantined_hosts_count": 0,
                "error": str(exc),
            }

    def ensure_infrastructure(self) -> bool:
        if not self.is_configured():
            return False
        try:
            self._request(
                self.block_endpoint,
                method="POST",
                payload={
                    "group": self.quarantine_group,
                    "rule": self.quarantine_rule,
                    "action": "ensure_group",
                },
            )
            return True
        except Exception:
            return False

    def block_device(
        self,
        ip_address: str,
        hostname: str | None = None,
        mac_address: str | None = None,
    ) -> dict[str, Any]:
        if self.is_protected_ip(ip_address):
            return {
                "status": "protected",
                "ip_address": ip_address,
                "vendor": self.vendor,
                "reason": f"IP {ip_address} is a protected infrastructure IP and cannot be blocked.",
            }
        if not self.is_configured():
            return {
                "status": "simulated",
                "ip_address": ip_address,
                "vendor": self.vendor,
                "reason": f"{self.vendor_title} not configured. Running in simulation mode.",
            }
        try:
            self._request(
                self.block_endpoint,
                method="POST",
                payload={
                    "ip_address": ip_address,
                    "hostname": hostname,
                    "mac_address": mac_address,
                    "quarantine_group": self.quarantine_group,
                    "quarantine_rule": self.quarantine_rule,
                },
            )
            return {
                "status": "blocked",
                "ip_address": ip_address,
                "vendor": self.vendor,
                "message": f"Device {ip_address} quarantined on {self.vendor_title} ({self.quarantine_group}).",
            }
        except Exception as exc:
            return {
                "status": "error",
                "ip_address": ip_address,
                "vendor": self.vendor,
                "error": str(exc),
            }

    def allow_device(
        self,
        ip_address: str,
        mac_address: str | None = None,
    ) -> dict[str, Any]:
        if not self.is_configured():
            return {
                "status": "simulated",
                "ip_address": ip_address,
                "vendor": self.vendor,
                "reason": f"{self.vendor_title} not configured. Running in simulation mode.",
            }
        try:
            self._request(
                self.allow_endpoint,
                method="POST",
                payload={
                    "ip_address": ip_address,
                    "mac_address": mac_address,
                    "quarantine_group": self.quarantine_group,
                },
            )
            return {
                "status": "allowed",
                "ip_address": ip_address,
                "vendor": self.vendor,
                "message": f"Device {ip_address} unblocked on {self.vendor_title}.",
            }
        except Exception as exc:
            return {
                "status": "error",
                "ip_address": ip_address,
                "vendor": self.vendor,
                "error": str(exc),
            }

    def get_status(self) -> dict[str, Any]:
        parsed = urlparse(self.management_url) if self.management_url else None
        return {
            "vendor": self.vendor,
            "vendor_title": self.vendor_title,
            "configured": self.is_configured(),
            "management_url": self.management_url,
            "firewall_ip": parsed.hostname if parsed else None,
            "port": parsed.port if parsed else self.default_port,
            "has_api_key": bool(self.api_key),
            "quarantine_group": self.quarantine_group,
            "quarantine_rule": self.quarantine_rule,
            "tls_verification": self.verify_tls,
            "auth_type": self.auth_type,
        }


class PaloAltoDriver(GenericEnterpriseRESTFirewallDriver):
    vendor = "palo_alto"
    vendor_title = "Palo Alto Networks (PAN-OS)"
    description = "Palo Alto PA-Series & VM-Series NGFW using PAN-OS XML/REST API & Dynamic Address Groups"
    default_port = 443
    auth_type = "both"
    status_endpoint = "/restapi/v10.2/Objects/Addresses"
    block_endpoint = "/api/?type=user-id"
    allow_endpoint = "/api/?type=user-id"
    firmware_label = "PAN-OS 10.x/11.x"


class CheckPointDriver(GenericEnterpriseRESTFirewallDriver):
    vendor = "checkpoint"
    vendor_title = "Check Point Quantum (Gaia / R81)"
    description = "Check Point Quantum Security Gateway & SmartConsole Management Web API"
    default_port = 443
    auth_type = "both"
    status_endpoint = "/web_api/v1.9/show-hosts"
    block_endpoint = "/web_api/v1.9/add-host"
    allow_endpoint = "/web_api/v1.9/delete-host"
    firmware_label = "Check Point Gaia R81"


class JuniperSRXDriver(GenericEnterpriseRESTFirewallDriver):
    vendor = "juniper_srx"
    vendor_title = "Juniper Networks SRX (Junos OS)"
    description = "Juniper SRX Series Services Gateways using Junos REST / NETCONF API"
    default_port = 3000
    auth_type = "credentials"
    status_endpoint = "/rpc/get-software-information"
    block_endpoint = "/rpc/load-configuration"
    allow_endpoint = "/rpc/load-configuration"
    firmware_label = "Junos OS"


class SonicWallDriver(GenericEnterpriseRESTFirewallDriver):
    vendor = "sonicwall"
    vendor_title = "SonicWall NSa / TZ (SonicOS)"
    description = "SonicWall Next-Gen Firewalls using SonicOS 7 REST API address object groups"
    default_port = 443
    auth_type = "credentials"
    status_endpoint = "/api/sonicos/reporting/system"
    block_endpoint = "/api/sonicos/address-objects/ipv4"
    allow_endpoint = "/api/sonicos/address-objects/ipv4"
    firmware_label = "SonicOS 7.x"


class WatchGuardDriver(GenericEnterpriseRESTFirewallDriver):
    vendor = "watchguard"
    vendor_title = "WatchGuard Firebox (Fireware OS)"
    description = "WatchGuard Firebox appliances using Fireware RESTful API blocked sites list"
    default_port = 8080
    auth_type = "both"
    status_endpoint = "/v1/status/system"
    block_endpoint = "/v1/firewall/blocked-sites"
    allow_endpoint = "/v1/firewall/blocked-sites"
    firmware_label = "Fireware OS"


class UbiquitiUniFiDriver(GenericEnterpriseRESTFirewallDriver):
    vendor = "ubiquiti"
    vendor_title = "Ubiquiti UniFi Gateway / EdgeRouter"
    description = "Ubiquiti UniFi Dream Machine (UDM-Pro) & EdgeOS Firewall Group API"
    default_port = 443
    auth_type = "both"
    status_endpoint = "/proxy/network/api/s/default/stat/health"
    block_endpoint = "/proxy/network/api/s/default/rest/firewallgroup"
    allow_endpoint = "/proxy/network/api/s/default/rest/firewallgroup"
    firmware_label = "UniFi OS / EdgeOS"


class ArubaGatewayDriver(GenericEnterpriseRESTFirewallDriver):
    vendor = "aruba"
    vendor_title = "HPE Aruba Networking Gateway (ArubaOS)"
    description = "HPE Aruba Mobility Conductor & Branch Gateways using ArubaOS REST API"
    default_port = 4343
    auth_type = "credentials"
    status_endpoint = "/v1/configuration/object/version"
    block_endpoint = "/v1/configuration/object/user_role"
    allow_endpoint = "/v1/configuration/object/user_role"
    firmware_label = "ArubaOS 8.x/10.x"


class HuaweiUSGDriver(GenericEnterpriseRESTFirewallDriver):
    vendor = "huawei_usg"
    vendor_title = "Huawei HiSecEngine USG (VRP)"
    description = "Huawei USG6000E Series Next-Gen Firewalls using RESTCONF / Northbound API"
    default_port = 8443
    auth_type = "credentials"
    status_endpoint = "/restconf/data/huawei-system:system"
    block_endpoint = "/restconf/data/huawei-address-set:address-set"
    allow_endpoint = "/restconf/data/huawei-address-set:address-set"
    firmware_label = "Huawei VRP USG"
