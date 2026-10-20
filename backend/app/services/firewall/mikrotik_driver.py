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


class MikrotikDriver(BaseFirewallDriver):
    """
    Driver for MikroTik RouterOS v7+ Routers and Firewalls (e.g. RouterBOARD).
    Utilizes the native RouterOS REST API to manage firewall address-lists
    and forward chain quarantine drop rules.
    """

    vendor = "mikrotik"
    vendor_title = "MikroTik RouterOS"
    description = "MikroTik RouterOS REST API address-list & firewall filter integration"
    default_port = 443
    auth_type = "credentials"

    def is_configured(self) -> bool:
        return bool(self.management_url and self.username and self.password)

    def _get_headers(self) -> dict[str, str]:
        creds = f"{self.username}:{self.password}".encode("utf-8")
        b64 = base64.b64encode(creds).decode("utf-8")
        return {
            "Authorization": f"Basic {b64}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _rest_request(
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
            logger.error(f"MikroTik REST API error at {url}: {exc}")
            raise RuntimeError(f"MikroTik communication failure: {exc}") from exc

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
                "error": "MikroTik RouterOS is not configured (missing URL or username/password)",
            }

        parsed = urlparse(self.management_url)
        firewall_ip = parsed.hostname

        try:
            res_data = self._rest_request("/rest/system/resource")
            if isinstance(res_data, dict) and "http_error" in res_data:
                return {
                    "connected": False,
                    "vendor": self.vendor,
                    "vendor_title": self.vendor_title,
                    "firewall_ip": firewall_ip,
                    "api_version": None,
                    "quarantine_rule_active": False,
                    "quarantined_hosts_count": 0,
                    "error": f"HTTP {res_data['http_error']}: {res_data.get('reason')}",
                }

            version = res_data.get("version") if isinstance(res_data, dict) else "RouterOS"
            board_name = res_data.get("board-name", "") if isinstance(res_data, dict) else ""
            api_ver = f"{version} ({board_name})" if board_name else str(version)

            # Check address list count
            addr_list_data = self._rest_request(f"/rest/ip/firewall/address-list?list={self.quarantine_group}")
            hosts_count = len(addr_list_data) if isinstance(addr_list_data, list) else 0

            # Check filter rule
            filter_data = self._rest_request("/rest/ip/firewall/filter?comment=NETOPS_Quarantine_Block")
            rule_active = bool(isinstance(filter_data, list) and len(filter_data) > 0)

            return {
                "connected": True,
                "vendor": self.vendor,
                "vendor_title": self.vendor_title,
                "firewall_ip": firewall_ip,
                "api_version": api_ver,
                "quarantine_rule_active": rule_active,
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
            # Check if filter rule exists
            rules = self._rest_request("/rest/ip/firewall/filter?comment=NETOPS_Quarantine_Block")
            if not isinstance(rules, list) or len(rules) == 0:
                self._rest_request(
                    "/rest/ip/firewall/filter",
                    method="PUT",
                    payload={
                        "chain": "forward",
                        "src-address-list": self.quarantine_group,
                        "action": "drop",
                        "comment": "NETOPS_Quarantine_Block",
                        "place-before": "0",
                    },
                )
            return True
        except Exception as exc:
            logger.warning(f"MikroTik ensure_infrastructure: {exc}")
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
                "reason": "MikroTik RouterOS is not configured. Running in simulation mode.",
            }

        try:
            # Check if already in address-list
            existing = self._rest_request(f"/rest/ip/firewall/address-list?address={ip_address}&list={self.quarantine_group}")
            if not isinstance(existing, list) or len(existing) == 0:
                self._rest_request(
                    "/rest/ip/firewall/address-list",
                    method="PUT",
                    payload={
                        "list": self.quarantine_group,
                        "address": ip_address,
                        "comment": f"NETOPS Quarantined Host {hostname or ''}".strip(),
                    },
                )

            return {
                "status": "blocked",
                "ip_address": ip_address,
                "vendor": self.vendor,
                "quarantine_group": self.quarantine_group,
                "message": f"Device {ip_address} added to MikroTik address-list '{self.quarantine_group}'.",
            }
        except Exception as exc:
            logger.error(f"MikroTik block failed for {ip_address}: {exc}")
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
                "reason": "MikroTik RouterOS is not configured. Running in simulation mode.",
            }

        try:
            # Query entry ID for this address
            entries = self._rest_request(f"/rest/ip/firewall/address-list?address={ip_address}&list={self.quarantine_group}")
            if isinstance(entries, list):
                for entry in entries:
                    entry_id = entry.get(".id")
                    if entry_id:
                        self._rest_request(
                            f"/rest/ip/firewall/address-list/{urllib.parse.quote(entry_id)}",
                            method="DELETE",
                        )

            return {
                "status": "allowed",
                "ip_address": ip_address,
                "vendor": self.vendor,
                "message": f"Device {ip_address} removed from MikroTik address-list '{self.quarantine_group}'.",
            }
        except Exception as exc:
            logger.error(f"MikroTik allow failed for {ip_address}: {exc}")
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
            "quarantine_rule": self.quarantine_rule,
            "tls_verification": self.verify_tls,
            "auth_type": self.auth_type,
        }
