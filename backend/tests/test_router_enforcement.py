from unittest.mock import MagicMock, patch

from backend.app.services.router.base import BaseRouterDriver
from backend.app.services.router.tenda_driver import TendaRouterDriver
from backend.app.services.router.universal_arp_driver import UniversalArpRouterDriver
from backend.app.services.router.enterprise_drivers import (
    TpLinkRouterDriver,
    MikrotikRouterDriver,
    OpenwrtRouterDriver,
    AsusRouterDriver,
    NetgearRouterDriver,
)
from backend.app.services.router.manager import (
    create_router_driver,
    get_active_router_driver,
    list_supported_router_vendors,
    detect_default_gateway_ip,
)


def test_list_supported_router_vendors():
    vendors = list_supported_router_vendors()
    vendor_ids = [v["id"] for v in vendors]
    assert "universal_arp" in vendor_ids
    assert "tenda" in vendor_ids
    assert "tplink" in vendor_ids
    assert "mikrotik" in vendor_ids
    assert "openwrt" in vendor_ids
    assert "asus" in vendor_ids
    assert "netgear" in vendor_ids


def test_create_router_driver():
    drv_tenda = create_router_driver({"vendor": "tenda"})
    assert isinstance(drv_tenda, TendaRouterDriver)

    drv_tplink = create_router_driver({"vendor": "tplink"})
    assert isinstance(drv_tplink, TpLinkRouterDriver)

    drv_mikrotik = create_router_driver({"vendor": "mikrotik"})
    assert isinstance(drv_mikrotik, MikrotikRouterDriver)

    drv_openwrt = create_router_driver({"vendor": "openwrt"})
    assert isinstance(drv_openwrt, OpenwrtRouterDriver)

    drv_asus = create_router_driver({"vendor": "asus"})
    assert isinstance(drv_asus, AsusRouterDriver)

    drv_netgear = create_router_driver({"vendor": "netgear"})
    assert isinstance(drv_netgear, NetgearRouterDriver)

    drv_univ = create_router_driver({"vendor": "universal_arp"})
    assert isinstance(drv_univ, UniversalArpRouterDriver)


def test_universal_arp_driver_block_and_allow():
    driver = UniversalArpRouterDriver()
    with patch("backend.app.services.router.universal_arp_driver.add_iptables_quarantine_ip") as mock_ipt:
        with patch("backend.app.services.router.universal_arp_driver.quarantine_device_l2") as mock_l2:
            res_block = driver.block_device("192.168.0.55", "AA:BB:CC:DD:EE:55", "TestLaptop")
            assert res_block["status"] == "blocked"
            mock_ipt.assert_called_once()
            mock_l2.assert_called_once()

    with patch("backend.app.services.router.universal_arp_driver.remove_iptables_quarantine_ip") as mock_rm_ipt:
        with patch("backend.app.services.router.universal_arp_driver.restore_device_l2") as mock_restore:
            res_allow = driver.allow_device("192.168.0.55", "AA:BB:CC:DD:EE:55")
            assert res_allow["status"] == "allowed"
            mock_rm_ipt.assert_called_once()
            mock_restore.assert_called_once()


def test_universal_arp_driver_protected_ip():
    driver = UniversalArpRouterDriver()
    res = driver.block_device("127.0.0.1", "00:00:00:00:00:00")
    assert res["status"] == "protected"


def test_tenda_driver_block_and_allow():
    driver = TendaRouterDriver({"management_url": "http://192.168.0.1"})
    with patch("urllib.request.urlopen") as mock_url:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"status": 0}'
        mock_url.return_value.__enter__.return_value = mock_resp

        res_block = driver.block_device("192.168.0.60", "AA:BB:CC:DD:EE:60", "Phone")
        assert res_block["status"] == "blocked"

        res_allow = driver.allow_device("192.168.0.60", "AA:BB:CC:DD:EE:60")
        assert res_allow["status"] == "allowed"


def test_detect_default_gateway_ip():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="default via 192.168.0.1 dev wlan0 proto dhcp metric 600\n")
        assert detect_default_gateway_ip() == "192.168.0.1"


def test_get_active_router_driver_default():
    with patch("backend.app.services.router.manager.detect_default_gateway_ip", return_value="192.168.0.1"):
        driver = get_active_router_driver(db=None)
        assert isinstance(driver, (TendaRouterDriver, UniversalArpRouterDriver))
