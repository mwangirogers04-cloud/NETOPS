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


class PfSenseDriver(BaseFirewallDriver):
    """
    Driver for pfSense and OPNsense Open-Source Firewalls.
    Supports OPNsense core REST API & pfSense FauxAPI / REST API
    for managing firewall alias tables and packet filter block lists.
    """

    vendor = "pfsense"
    vendor_title = "pfSense / OPNsense"
    description = "pfSense & OPNsense REST API firewall alias and packet filter integration"
    default_port = 443
    auth_type = "both"  # Supports API key/secret or admin credentials

    def is_configured(self) -> bool:
        return bool(self.management_url and (self.api_key or (self.username and self.password)))

    def _get_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key and self.password:
            # OPNsense API Key and Secret
            creds = f"{self.api_key}:{self.password}".encode("utf-8")
            headers["Authorization"] = f"Basic {base64.b64encode(creds).decode('utf-8')}"
        elif self.username and self.password:
            creds = f"{self.username}:{self.password}".encode("utf-8")
            headers["Authorization"] = f"Basic {base64.b64encode(creds).decode('utf-8')}"
        elif self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
            headers["fauxapi-auth"] = self.api_key
        return headers

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
            logger.error(f"pfSense/OPNsense API error at {url}: {exc}")
            raise RuntimeError(f"pfSense/OPNsense communication failure: {exc}") from exc

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
                "error": "pfSense / OPNsense is not configured (missing URL or API key)",
            }

        parsed = urlparse(self.management_url)
        firewall_ip = parsed.hostname

        try:
            # Query status
            status_data = self._request("/api/core/system/status")
            if isinstance(status_data, dict) and "http_error" in status_data:
                # Try pfSense REST API endpoint /api/v1/system/version
                status_data = self._request("/api/v1/system/version")

            if isinstance(status_data, dict) and "http_error" in status_data:
                return {
                    "connected": False,
                    "vendor": self.vendor,
                    "vendor_title": self.vendor_title,
                    "firewall_ip": firewall_ip,
                    "api_version": None,
                    "quarantine_rule_active": False,
                    "quarantined_hosts_count": 0,
                    "error": f"HTTP {status_data['http_error']}: {status_data.get('reason')}",
                }

            version = "OPNsense / pfSense"
            if isinstance(status_data, dict):
                version = status_data.get("product_version") or status_data.get("data", {}).get("version", version)

            # Check alias list
            alias_res = self._request(f"/api/firewall/alias_util/list/{self.quarantine_group}")
            hosts_count = len(alias_res.get("rows", [])) if isinstance(alias_res, dict) and "rows" in alias_res else 0

            return {
                "connected": True,
                "vendor": self.vendor,
                "vendor_title": self.vendor_title,
                "firewall_ip": firewall_ip,
                "api_version": str(version),
                "quarantine_rule_active": True,
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
                "reason": "pfSense / OPNsense is not configured. Running in simulation mode.",
            }

        try:
            self._request(
                f"/api/firewall/alias_util/add/{self.quarantine_group}",
                method="POST",
                payload={"address": ip_address},
            )
            return {
                "status": "blocked",
                "ip_address": ip_address,
                "vendor": self.vendor,
                "alias": self.quarantine_group,
                "message": f"Device {ip_address} added to pfSense/OPNsense alias '{self.quarantine_group}'.",
            }
        except Exception as exc:
            logger.error(f"pfSense block failed for {ip_address}: {exc}")
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
                "reason": "pfSense / OPNsense is not configured. Running in simulation mode.",
            }

        try:
            self._request(
                f"/api/firewall/alias_util/delete/{self.quarantine_group}",
                method="POST",
                payload={"address": ip_address},
            )
            return {
                "status": "allowed",
                "ip_address": ip_address,
                "vendor": self.vendor,
                "message": f"Device {ip_address} removed from pfSense/OPNsense alias '{self.quarantine_group}'.",
            }
        except Exception as exc:
            logger.error(f"pfSense allow failed for {ip_address}: {exc}")
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
            "quarantine_group": self.quarantine_group,
            "tls_verification": self.verify_tls,
            "auth_type": self.auth_type,
        }
