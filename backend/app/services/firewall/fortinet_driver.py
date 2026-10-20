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


class FortinetDriver(BaseFirewallDriver):
    """
    Driver for Fortinet FortiGate Firewalls running FortiOS.
    Interacts via the FortiOS REST API (TCP 443/8443) using an API token
    or administrator credentials to manage address objects and quarantine groups.
    """

    vendor = "fortinet"
    vendor_title = "Fortinet FortiGate (FortiOS)"
    description = "Fortinet FortiGate REST API integration for dynamic address quarantine"
    default_port = 443
    auth_type = "api_token"

    def is_configured(self) -> bool:
        return bool(self.management_url and (self.api_key or (self.username and self.password)))

    def _get_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _api_request(
        self,
        endpoint: str,
        method: str = "GET",
        payload: dict | None = None,
        timeout: float = 6.0,
    ) -> dict[str, Any]:
        url = f"{self.management_url.rstrip('/')}{endpoint}"
        if not self.api_key and self.username and self.password:
            # Pass basic auth / access_token query param
            pass

        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(url, data=data, headers=self._get_headers(), method=method)

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            try:
                err_body = exc.read().decode("utf-8", errors="replace")
                return {"http_error": exc.code, "reason": exc.reason, "body": err_body}
            except Exception:
                return {"http_error": exc.code, "reason": str(exc)}
        except Exception as exc:
            logger.error(f"FortiGate API request to {url} failed: {exc}")
            raise RuntimeError(f"FortiGate communication failure: {exc}") from exc

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
                "error": "Fortinet FortiGate is not configured (missing URL or API token)",
            }

        parsed = urlparse(self.management_url)
        firewall_ip = parsed.hostname

        try:
            # Query system status
            status_data = self._api_request("/api/v2/monitor/system/status")
            if "http_error" in status_data:
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

            version = status_data.get("version") or status_data.get("results", {}).get("version", "FortiOS")
            
            # Check quarantine group
            group_res = self._api_request(f"/api/v2/cmdb/firewall/addrgrp/{self.quarantine_group}")
            group_active = False
            hosts_count = 0
            if "results" in group_res and isinstance(group_res["results"], list) and group_res["results"]:
                group_active = True
                members = group_res["results"][0].get("member", [])
                hosts_count = len(members)

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
        if not self.is_configured():
            return False
        try:
            # Create dummy host address object if needed
            self._api_request(
                "/api/v2/cmdb/firewall/address",
                method="POST",
                payload={
                    "name": "NETOPS_DUMMY_HOST",
                    "subnet": "192.0.2.254 255.255.255.255",
                    "comment": "NETOPS Infrastructure Anchor",
                },
            )
            # Create address group
            self._api_request(
                "/api/v2/cmdb/firewall/addrgrp",
                method="POST",
                payload={
                    "name": self.quarantine_group,
                    "member": [{"name": "NETOPS_DUMMY_HOST"}],
                    "comment": "NETOPS Quarantine Block Group",
                },
            )
            return True
        except Exception as exc:
            logger.warning(f"FortiGate ensure_infrastructure warning: {exc}")
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
                "reason": "Fortinet FortiGate is not configured. Running in simulation mode.",
            }

        addr_name = f"NETOPS_{ip_address.replace('.', '_')}"
        try:
            # 1. Create or update host address object
            self._api_request(
                "/api/v2/cmdb/firewall/address",
                method="POST",
                payload={
                    "name": addr_name,
                    "subnet": f"{ip_address} 255.255.255.255",
                    "comment": f"NETOPS Quarantined Host {hostname or ''}".strip(),
                },
            )

            # 2. Add address to quarantine group
            self._api_request(
                f"/api/v2/cmdb/firewall/addrgrp/{self.quarantine_group}/member",
                method="POST",
                payload={"name": addr_name},
            )

            return {
                "status": "blocked",
                "ip_address": ip_address,
                "vendor": self.vendor,
                "address_name": addr_name,
                "quarantine_group": self.quarantine_group,
                "message": f"Device {ip_address} added to FortiGate quarantine group {self.quarantine_group}.",
            }
        except Exception as exc:
            logger.error(f"FortiGate block failed for {ip_address}: {exc}")
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
                "reason": "Fortinet FortiGate is not configured. Running in simulation mode.",
            }

        addr_name = f"NETOPS_{ip_address.replace('.', '_')}"
        try:
            # 1. Remove address from quarantine group
            self._api_request(
                f"/api/v2/cmdb/firewall/addrgrp/{self.quarantine_group}/member/{addr_name}",
                method="DELETE",
            )
            # 2. Delete host address object
            self._api_request(
                f"/api/v2/cmdb/firewall/address/{addr_name}",
                method="DELETE",
            )
            return {
                "status": "allowed",
                "ip_address": ip_address,
                "vendor": self.vendor,
                "message": f"Device {ip_address} removed from FortiGate quarantine group.",
            }
        except Exception as exc:
            logger.error(f"FortiGate allow failed for {ip_address}: {exc}")
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
