import logging
import ssl
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from ..config import settings

logger = logging.getLogger(__name__)

PROTECTED_IPS = {
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "192.168.0.10",   # Sophos Firewall appliance
    "192.168.0.1",    # Gateway
    "192.168.0.13",   # NETOPS server eth0
    "192.168.0.101",  # NETOPS server wlan0
}

GROUP_NAME = "NETOPS_Quarantined_Hosts"
DUMMY_HOST = "NETOPS_DUMMY_HOST"
RULE_NAME = "NETOPS_Quarantine_Block"


def is_sophos_configured() -> bool:
    """Check if Sophos firewall credentials and URL are configured."""
    url = settings.sophos_base_url.strip()
    user = settings.sophos_username.strip()
    pwd = settings.sophos_password.strip()
    return bool(url and user and pwd)


def _send_sophos_xml(req_xml: str, timeout: float = 8.0) -> str:
    """Send an authenticated XML request to the Sophos WebConsole APIController."""
    base_url = settings.sophos_base_url.strip().rstrip("/")
    api_url = f"{base_url}/webconsole/APIController"

    ctx = ssl.create_default_context()
    if not settings.sophos_verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    data = urllib.parse.urlencode({"reqxml": req_xml}).encode("utf-8")
    req = urllib.request.Request(api_url, data=data, method="POST")

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        logger.error(f"Failed to communicate with Sophos Firewall at {api_url}: {exc}")
        raise RuntimeError(f"Sophos Firewall communication failure: {exc}") from exc


def ensure_sophos_infrastructure() -> bool:
    """
    Ensure the dummy host, quarantine group, and Top Drop firewall rule exist on Sophos.
    """
    if not is_sophos_configured():
        return False

    user = settings.sophos_username.strip()
    pwd = settings.sophos_password.strip()

    try:
        # 1. Ensure dummy host
        xml_dummy = f"""<Request>
  <Login><Username>{user}</Username><Password>{pwd}</Password></Login>
  <Set>
    <IPHost transactionid="">
      <Name>{DUMMY_HOST}</Name>
      <IPFamily>IPv4</IPFamily>
      <HostType>IP</HostType>
      <IPAddress>192.0.2.254</IPAddress>
    </IPHost>
  </Set>
</Request>"""
        _send_sophos_xml(xml_dummy)

        # 2. Ensure IPHostGroup
        xml_group = f"""<Request>
  <Login><Username>{user}</Username><Password>{pwd}</Password></Login>
  <Set>
    <IPHostGroup transactionid="">
      <Name>{GROUP_NAME}</Name>
      <Description>Managed by NETOPS Platform for live device quarantine</Description>
      <IPFamily>IPv4</IPFamily>
      <HostList>
        <Host>{DUMMY_HOST}</Host>
      </HostList>
    </IPHostGroup>
  </Set>
</Request>"""
        _send_sophos_xml(xml_group)

        # 3. Ensure Top Drop FirewallRule
        xml_rule = f"""<Request>
  <Login><Username>{user}</Username><Password>{pwd}</Password></Login>
  <Set>
    <FirewallRule transactionid="">
      <Name>{RULE_NAME}</Name>
      <Description>Managed by NETOPS: Quarantines and disconnects blocked LAN devices from network and Internet</Description>
      <IPFamily>IPv4</IPFamily>
      <Status>Enable</Status>
      <Position>Top</Position>
      <PolicyType>Network</PolicyType>
      <NetworkPolicy>
        <Action>Drop</Action>
        <LogTraffic>Enable</LogTraffic>
        <SkipLocalDestined>Disable</SkipLocalDestined>
        <SourceZones>
          <Zone>LAN</Zone>
        </SourceZones>
        <SourceNetworks>
          <Network>{GROUP_NAME}</Network>
        </SourceNetworks>
        <DestinationZones>
          <Zone>WAN</Zone>
        </DestinationZones>
        <Schedule>All The Time</Schedule>
      </NetworkPolicy>
    </FirewallRule>
  </Set>
</Request>"""
        _send_sophos_xml(xml_rule)
        return True
    except Exception as exc:
        logger.warning(f"Error initializing Sophos infrastructure: {exc}")
        return False


def get_current_quarantined_hosts() -> list[str]:
    """Retrieve all host names currently enrolled in NETOPS_Quarantined_Hosts."""
    if not is_sophos_configured():
        return []

    user = settings.sophos_username.strip()
    pwd = settings.sophos_password.strip()

    req_xml = f"""<Request>
  <Login><Username>{user}</Username><Password>{pwd}</Password></Login>
  <Get>
    <IPHostGroup>
      <Name>{GROUP_NAME}</Name>
    </IPHostGroup>
  </Get>
</Request>"""

    try:
        raw_xml = _send_sophos_xml(req_xml)
        root = ET.fromstring(raw_xml)
        for grp in root.findall(".//IPHostGroup"):
            name_el = grp.find("Name")
            if name_el is not None and name_el.text == GROUP_NAME:
                return [h.text for h in grp.findall("HostList/Host") if h.text]
        return [DUMMY_HOST]
    except Exception as exc:
        logger.error(f"Failed to fetch Sophos quarantined host group: {exc}")
        return [DUMMY_HOST]


def sophos_block_device(ip_address: str, hostname: str | None = None) -> dict:
    """
    Block and disconnect a device's IP address by placing it in NETOPS_Quarantined_Hosts.
    The top drop firewall rule on Sophos will immediately drop all traffic from this host.
    """
    if not ip_address or not ip_address.strip():
        return {"status": "skipped", "reason": "No IP address provided"}

    clean_ip = ip_address.strip()
    if clean_ip in PROTECTED_IPS:
        logger.warning(f"Blocked attempt to quarantine protected IP {clean_ip}")
        return {"status": "protected", "reason": f"{clean_ip} is a protected infrastructure IP"}

    if not is_sophos_configured():
        return {"status": "simulated", "reason": "Sophos integration not configured"}

    user = settings.sophos_username.strip()
    pwd = settings.sophos_password.strip()
    host_name = f"NETOPS_BLOCK_{clean_ip.replace('.', '_')}"

    try:
        # 1. Create or ensure IPHost exists on Sophos
        xml_host = f"""<Request>
  <Login><Username>{user}</Username><Password>{pwd}</Password></Login>
  <Set>
    <IPHost transactionid="">
      <Name>{host_name}</Name>
      <IPFamily>IPv4</IPFamily>
      <HostType>IP</HostType>
      <IPAddress>{clean_ip}</IPAddress>
    </IPHost>
  </Set>
</Request>"""
        _send_sophos_xml(xml_host)

        # 2. Get current members and add host_name
        current_members = get_current_quarantined_hosts()
        if host_name not in current_members:
            current_members.append(host_name)

        if DUMMY_HOST not in current_members:
            current_members.insert(0, DUMMY_HOST)

        host_tags = "\n".join(f"        <Host>{m}</Host>" for m in current_members)
        xml_update_group = f"""<Request>
  <Login><Username>{user}</Username><Password>{pwd}</Password></Login>
  <Set>
    <IPHostGroup transactionid="">
      <Name>{GROUP_NAME}</Name>
      <HostList>
{host_tags}
      </HostList>
    </IPHostGroup>
  </Set>
</Request>"""
        _send_sophos_xml(xml_update_group)

        logger.info(f"Sophos Firewall: Successfully quarantined device {clean_ip} ({host_name})")
        return {
            "status": "blocked",
            "ip_address": clean_ip,
            "host_name": host_name,
            "firewall": "Sophos XGS/XG",
            "rule": RULE_NAME,
        }
    except Exception as exc:
        logger.error(f"Failed to block device {clean_ip} on Sophos: {exc}")
        return {"status": "error", "error": str(exc), "ip_address": clean_ip}


def sophos_allow_device(ip_address: str) -> dict:
    """
    Remove a device's IP from NETOPS_Quarantined_Hosts, restoring its network and Internet access.
    """
    if not ip_address or not ip_address.strip():
        return {"status": "skipped", "reason": "No IP address provided"}

    clean_ip = ip_address.strip()
    if not is_sophos_configured():
        return {"status": "simulated", "reason": "Sophos integration not configured"}

    user = settings.sophos_username.strip()
    pwd = settings.sophos_password.strip()
    host_name = f"NETOPS_BLOCK_{clean_ip.replace('.', '_')}"

    try:
        # 1. Remove host_name from IPHostGroup
        current_members = get_current_quarantined_hosts()
        updated_members = [m for m in current_members if m != host_name]

        if not updated_members or DUMMY_HOST not in updated_members:
            updated_members = [DUMMY_HOST]

        host_tags = "\n".join(f"        <Host>{m}</Host>" for m in updated_members)
        xml_update_group = f"""<Request>
  <Login><Username>{user}</Username><Password>{pwd}</Password></Login>
  <Set>
    <IPHostGroup transactionid="">
      <Name>{GROUP_NAME}</Name>
      <HostList>
{host_tags}
      </HostList>
    </IPHostGroup>
  </Set>
</Request>"""
        _send_sophos_xml(xml_update_group)

        # 2. Remove IPHost object
        xml_remove_host = f"""<Request>
  <Login><Username>{user}</Username><Password>{pwd}</Password></Login>
  <Remove>
    <IPHost>
      <Name>{host_name}</Name>
    </IPHost>
  </Remove>
</Request>"""
        try:
            _send_sophos_xml(xml_remove_host)
        except Exception:
            pass  # Host may not exist

        logger.info(f"Sophos Firewall: Successfully unblocked device {clean_ip}")
        return {
            "status": "allowed",
            "ip_address": clean_ip,
            "firewall": "Sophos XGS/XG",
        }
    except Exception as exc:
        logger.error(f"Failed to unblock device {clean_ip} on Sophos: {exc}")
        return {"status": "error", "error": str(exc), "ip_address": clean_ip}


def sophos_test_connection() -> dict:
    """Test connectivity, credentials, and query status of Sophos Firewall."""
    if not is_sophos_configured():
        return {
            "connected": False,
            "error": "Sophos credentials not fully configured in settings",
        }

    user = settings.sophos_username.strip()
    pwd = settings.sophos_password.strip()

    req_xml = f"""<Request>
  <Login><Username>{user}</Username><Password>{pwd}</Password></Login>
  <Get>
    <FirewallRule>
      <Name>{RULE_NAME}</Name>
    </FirewallRule>
  </Get>
</Request>"""

    try:
        raw_xml = _send_sophos_xml(req_xml)
        root = ET.fromstring(raw_xml)
        login_status = root.findtext(".//Login/status")
        api_ver = root.attrib.get("APIVersion", "Unknown")

        if login_status and "Successful" in login_status:
            members = get_current_quarantined_hosts()
            active_quarantined = [m for m in members if m != DUMMY_HOST]
            return {
                "connected": True,
                "api_version": api_ver,
                "quarantine_rule_active": True,
                "firewall_ip": urlparse(settings.sophos_base_url).hostname,
                "quarantined_hosts_count": len(active_quarantined),
                "quarantined_hosts": active_quarantined,
            }
        return {
            "connected": False,
            "error": f"Login returned: {login_status}",
        }
    except Exception as exc:
        return {
            "connected": False,
            "error": str(exc),
        }
