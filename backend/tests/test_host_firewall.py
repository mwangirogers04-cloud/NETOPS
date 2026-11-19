import platform
from unittest.mock import MagicMock, patch

from agent import host_firewall


def test_resolve_server_ips_explicit_ip():
    ips = host_firewall._resolve_server_ips("http://192.168.0.50:8000")
    assert "192.168.0.50" in ips


def test_resolve_server_ips_fallback():
    ips = host_firewall._resolve_server_ips("invalid://nonexistent-local-domain-xyz:9999")
    assert len(ips) > 0
    assert any(ip in ("127.0.0.1", "192.168.0.13", "192.168.0.101") for ip in ips)


def test_is_self_exempt_developer_machine():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="3: wlan0    inet 192.168.0.101/24 brd 192.168.0.255 scope global dynamic noprefixroute wlan0"
        )
        assert host_firewall.is_self_exempt() is True


def test_quarantine_host_exempt():
    with patch.object(host_firewall, "is_self_exempt", return_value=True):
        res = host_firewall.quarantine_host("http://192.168.0.101:8000")
        assert res["status"] == "exempt"
        assert "protected" in res["reason"].lower() or "developer" in res["reason"].lower()


@patch("subprocess.run")
def test_quarantine_linux_commands(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
    with patch.object(host_firewall, "is_self_exempt", return_value=False):
        with patch("platform.system", return_value="Linux"):
            res = host_firewall.quarantine_host("http://10.0.0.1:8000")
            assert res["status"] == "quarantined"
            assert "10.0.0.1" in res["server_ips_whitelisted"]


@patch("subprocess.run")
def test_release_linux_commands(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
    with patch("platform.system", return_value="Linux"):
        res = host_firewall.release_host()
        assert res["status"] == "restored"
