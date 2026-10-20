import base64
import json
import logging
import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from .base import BaseFirewallDriver

logger = logging.getLogger(__name__)


class CiscoFirewallDriver(BaseFirewallDriver):
    """
    Driver for Cisco ASA & Secure Firewall (Firepower) running ASA REST API
    or Firepower Management Center (FMC) REST API.
    """

    vendor = "cisco_asa"
    vendor_title = "Cisco ASA / Firepower"
    description = "Cisco ASA & Firepower REST API network object quarantine integration"
    default_port = 443
    auth_type = "credentials"

    def is_configured(self) -> bool:
        return bool(self.management_url and self.username and self.password)

    def _get_headers(self) -> dict[str, str]:
        creds = f"{self.username}:{self.password}".encode("utf-8")
        return {
            "Authorization": f"Basic {base64.b64encode(creds).decode('utf-8')}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "NETOPS-Firewall-Client",
        }

    def _request(
        self,
        endpoint: str,
        method: str = "GET",
        payload: dict | None = None,
        timeout: float = 6.0,
    ) -> Any:
        url = f"{self.management_url.rstrip('/')}{endpoint}"
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(url, data=data, headers=self._get_headers(), method=method)

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as exc:
            try:
                err_body = exc.read().decode("utf-8", errors="replace")
                return {"http_error": exc.code, "reason": exc.reason, "body": err_body}
            except Exception:
                return {"http_error": exc.code, "reason": str(exc)}
        except Exception as exc:
            logger.error(f"Cisco ASA REST API error at {url}: {exc}")
            raise RuntimeError(f"Cisco ASA communication failure: {exc}") from exc

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
                "error": "Cisco ASA is not configured (missing URL or username/password)",
            }

        parsed = urlparse(self.management_url)
        firewall_ip = parsed.hostname

        try:
            # Query version
            ver_data = self._request("/api/monitoring/device/components/version")
            if isinstance(ver_data, dict) and "http_error" in ver_data:
                # Try tokenservice check
                token_test = self._request("/api/tokenservices", method="POST")
                if isinstance(token_test, dict) and "http_error" in token_test:
                    return {
                        "connected": False,
                        "vendor": self.vendor,
                        "vendor_title": self.vendor_title,
                        "firewall_ip": firewall_ip,
                        "api_version": None,
                        "quarantine_rule_active": False,
                        "quarantined_hosts_count": 0,
                        "error": f"HTTP {token_test['http_error']}: {token_test.get('reason')}",
                    }

            version = ver_data.get("asaVersion", "Cisco ASA / Firepower") if isinstance(ver_data, dict) else "Cisco ASA"

            # Check network object group
            group_res = self._request(f"/api/objects/networkobjectgroups/{self.quarantine_group}")
            group_active = False
            hosts_count = 0
            if isinstance(group_res, dict) and "members" in group_res:
                group_active = True
                hosts_count = len(group_res.get("members", []))

            return {
                "connected": True,
                "vendor": self.vendor,
                "vendor_title": self.vendor_title,
                "firewall_ip": firewall_ip,
                "api_version": str(version),
                "quarantine_rule_active": group_active,
                "quarantined_hosts_count": hosts_count,
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
        return True

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
                "reason": "Cisco ASA is not configured. Running in simulation mode.",
            }

        obj_name = f"NETOPS_{ip_address.replace('.', '_')}"
        try:
            # 1. Create network object
            self._request(
                "/api/objects/networkobjects",
                method="POST",
                payload={
                    "name": obj_name,
                    "host": {"kind": "IPv4Address", "value": ip_address},
                    "description": f"NETOPS Quarantined Host {hostname or ''}".strip(),
                },
            )
            # 2. Add to quarantine group
            self._request(
                f"/api/objects/networkobjectgroups/{self.quarantine_group}/members",
                method="POST",
                payload={"objectId": obj_name},
            )

            return {
                "status": "blocked",
                "ip_address": ip_address,
                "vendor": self.vendor,
                "message": f"Device {ip_address} added to Cisco ASA quarantine group '{self.quarantine_group}'.",
            }
        except Exception as exc:
            logger.error(f"Cisco ASA block failed for {ip_address}: {exc}")
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
                "reason": "Cisco ASA is not configured. Running in simulation mode.",
            }

        obj_name = f"NETOPS_{ip_address.replace('.', '_')}"
        try:
            self._request(
                f"/api/objects/networkobjectgroups/{self.quarantine_group}/members/{obj_name}",
                method="DELETE",
            )
            self._request(
                f"/api/objects/networkobjects/{obj_name}",
                method="DELETE",
            )
            return {
                "status": "allowed",
                "ip_address": ip_address,
                "vendor": self.vendor,
                "message": f"Device {ip_address} removed from Cisco ASA quarantine group.",
            }
        except Exception as exc:
            logger.error(f"Cisco ASA allow failed for {ip_address}: {exc}")
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
            "username": self.username,
            "quarantine_group": self.quarantine_group,
            "tls_verification": self.verify_tls,
            "auth_type": self.auth_type,
        }
