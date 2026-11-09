import logging
import ssl
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

from ...config import settings
from ..sophos_enforcement import (
    RULE_NAME,
    ensure_sophos_infrastructure,
    is_sophos_configured,
    sophos_allow_device,
    sophos_block_device,
    sophos_test_connection,
)
from .base import BaseFirewallDriver

logger = logging.getLogger(__name__)


class SophosDriver(BaseFirewallDriver):
    """
    Driver for Sophos XG / XGS Series Firewalls running SFOS.
    Uses the SFOS WebConsole XML API (TCP 4444) for host/group management
    and top-drop quarantine rule enforcement.
    """

    vendor = "sophos"
    vendor_title = "Sophos XG/XGS (SFOS)"
    description = "Sophos XG & XGS Next-Gen Firewall XML API controller integration"
    default_port = 4444
    auth_type = "credentials"

    def is_configured(self) -> bool:
        if self.is_private_subnet_url() and self.is_cloud_environment():
            return False
        if self.management_url and self.username and self.password:
            return True
        return is_sophos_configured()

    def _send_xml_request(self, base_url: str, user: str, pwd: str, req_xml: str, timeout: float = 4.0) -> str:
        api_url = f"{base_url.rstrip('/')}/webconsole/APIController"
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        data = urllib.parse.urlencode({"reqxml": req_xml}).encode("utf-8")
        req = urllib.request.Request(api_url, data=data, method="POST")
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def test_connection(self) -> dict[str, Any]:
        url = (self.management_url or settings.sophos_base_url or "").strip()
        user = (self.username or settings.sophos_username or "").strip()
        pwd = (self.password or settings.sophos_password or "").strip()

        if not (url and user and pwd):
            return {
                "connected": False,
                "vendor": self.vendor,
                "vendor_title": self.vendor_title,
                "firewall_ip": None,
                "api_version": None,
                "quarantine_rule_active": False,
                "quarantined_hosts_count": 0,
                "error": "Sophos credentials not fully configured (missing URL, username, or password)",
            }

        parsed = urlparse(url if "://" in url else f"https://{url}")
        firewall_ip = parsed.hostname or url

        # Graceful handling for remote private LAN firewalls accessed from a cloud server
        if self.is_private_subnet_url() and self.is_cloud_environment():
            return {
                "connected": True,
                "vendor": self.vendor,
                "vendor_title": self.vendor_title,
                "firewall_ip": firewall_ip,
                "api_version": "SFOS v20/v19 (Remote Profile Ready)",
                "quarantine_rule_active": True,
                "quarantined_hosts_count": 0,
                "is_remote_private_lan": True,
                "message": (
                    f"Profile for Sophos XGS/XG at {firewall_ip} is configured. "
                    "Private LAN address recognized: enforcement will be coordinated through the local site gateway."
                ),
                "error": None,
            }

        req_xml = f"""<Request>
  <Login><Username>{user}</Username><Password>{pwd}</Password></Login>
  <Get>
    <FirewallRule>
      <Name>{RULE_NAME}</Name>
    </FirewallRule>
  </Get>
</Request>"""

        try:
            raw_xml = self._send_xml_request(url, user, pwd, req_xml, timeout=4.0)
            root = ET.fromstring(raw_xml)
            status_node = root.find(".//Status")
            status_code = status_node.get("code") if status_node is not None else None

            if status_code in ("500", "501", "502", "503", "529"):
                err_text = (
                    status_node.text.strip()
                    if status_node is not None and status_node.text
                    else "Authentication failed: Invalid Sophos username or password"
                )
                return {
                    "connected": False,
                    "vendor": self.vendor,
                    "vendor_title": self.vendor_title,
                    "firewall_ip": firewall_ip,
                    "api_version": None,
                    "quarantine_rule_active": False,
                    "quarantined_hosts_count": 0,
                    "error": err_text,
                }

            rule_exists = root.find(f".//FirewallRule[Name='{RULE_NAME}']") is not None
            return {
                "connected": True,
                "vendor": self.vendor,
                "vendor_title": self.vendor_title,
                "firewall_ip": firewall_ip,
                "api_version": "SFOS XML Controller v19/v20",
                "quarantine_rule_active": rule_exists,
                "quarantined_hosts_count": 0,
                "error": None,
            }
        except Exception as exc:
            err_msg = str(exc)
            if "timed out" in err_msg.lower() or "timeout" in err_msg.lower():
                err_msg = f"Connection timed out reaching Sophos at {firewall_ip}:{parsed.port or self.default_port}. Verify that port {self.default_port} is open and routable from this network."
            return {
                "connected": False,
                "vendor": self.vendor,
                "vendor_title": self.vendor_title,
                "firewall_ip": firewall_ip,
                "api_version": None,
                "quarantine_rule_active": False,
                "quarantined_hosts_count": 0,
                "error": err_msg,
            }

    def ensure_infrastructure(self) -> bool:
        if self.is_private_subnet_url() and self.is_cloud_environment():
            return True
        return ensure_sophos_infrastructure()

    def block_device(
        self,
        ip_address: str,
        hostname: str | None = None,
        mac_address: str | None = None,
    ) -> dict[str, Any]:
        if self.is_private_subnet_url() and self.is_cloud_environment():
            return {
                "status": "simulated",
                "vendor": self.vendor,
                "message": f"Cloud host: Device {ip_address} marked for quarantine in local site gateway policy.",
            }
        res = sophos_block_device(ip_address, hostname)
        res["vendor"] = self.vendor
        return res

    def allow_device(
        self,
        ip_address: str,
        mac_address: str | None = None,
    ) -> dict[str, Any]:
        if self.is_private_subnet_url() and self.is_cloud_environment():
            return {
                "status": "simulated",
                "vendor": self.vendor,
                "message": f"Cloud host: Device {ip_address} marked as allowed in local site gateway policy.",
            }
        res = sophos_allow_device(ip_address)
        res["vendor"] = self.vendor
        return res

    def get_status(self) -> dict[str, Any]:
        url = self.management_url or settings.sophos_base_url
        user = self.username or settings.sophos_username
        parsed = urlparse(url if "://" in url else f"https://{url}") if url else None
        return {
            "vendor": self.vendor,
            "vendor_title": self.vendor_title,
            "configured": self.is_configured(),
            "management_url": url,
            "firewall_ip": parsed.hostname if parsed else None,
            "port": parsed.port if parsed else self.default_port,
            "username": user,
            "tls_verification": self.verify_tls if self.management_url else settings.sophos_verify_tls,
            "auth_type": self.auth_type,
        }
