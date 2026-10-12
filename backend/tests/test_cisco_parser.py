from backend.app.services.cisco_readonly import parse_mac_address_table


def test_parse_dynamic_mac_entry():
    output = """
          Mac Address Table
    -------------------------------------------

    Vlan    Mac Address       Type        Ports
    ----    -----------       --------    -----
      30    a44e.31ad.0e28    DYNAMIC     Gi0/7
      40    aabb.cc11.2233    STATIC      Gi0/8
    """

    result = parse_mac_address_table(output)

    assert result == [
        {
            "vlan_id": 30,
            "mac_address": "A4:4E:31:AD:0E:28",
            "interface": "Gi0/7",
            "entry_type": "DYNAMIC",
        },
        {
            "vlan_id": 40,
            "mac_address": "AA:BB:CC:11:22:33",
            "interface": "Gi0/8",
            "entry_type": "STATIC",
        },
    ]


def test_parse_empty_mac_table():
    output = """
    Mac Address Table
    -------------------------------------------
    Vlan    Mac Address       Type        Ports
    ----    -----------       --------    -----
    """

    assert parse_mac_address_table(output) == []

from unittest.mock import Mock, patch

from backend.app.services.cisco_readonly import get_mac_address_table


def test_get_mac_address_table_uses_readonly_connection():
    mock_connection = Mock()

    mock_connection.send_command.return_value = """
    Vlan    Mac Address       Type        Ports
    ----    -----------       --------    -----
      30    a44e.31ad.0e28    DYNAMIC     Gi0/7
    """

    with patch(
        "backend.app.services.cisco_readonly.connect_readonly",
        return_value=mock_connection,
    ):
        result = get_mac_address_table("192.0.2.10")

    assert result == [
        {
            "vlan_id": 30,
            "mac_address": "A4:4E:31:AD:0E:28",
            "interface": "Gi0/7",
            "entry_type": "DYNAMIC",
        }
    ]

    mock_connection.send_command.assert_called_once_with(
        "show mac address-table",
        read_timeout=30,
    )
    mock_connection.disconnect.assert_called_once()


def test_get_mac_address_table_disconnects_when_command_fails():
    from unittest.mock import MagicMock, patch

    from backend.app.services.cisco_readonly import (
        get_mac_address_table,
    )

    mock_connection = MagicMock()
    mock_connection.send_command.side_effect = RuntimeError(
        "Simulated command failure"
    )

    with patch(
        "backend.app.services.cisco_readonly.connect_readonly",
        return_value=mock_connection,
    ):
        try:
            get_mac_address_table("192.0.2.10")
        except RuntimeError as exc:
            assert str(exc) == "Simulated command failure"
        else:
            raise AssertionError("Expected RuntimeError was not raised")

    mock_connection.disconnect.assert_called_once_with()

def test_readonly_commands_disconnect_when_command_fails():
    from unittest.mock import Mock, patch

    from backend.app.services.cisco_readonly import (
        get_interface_status,
        get_vlan_brief,
    )

    for function, command in [
        (get_interface_status, "show interfaces status"),
        (get_vlan_brief, "show vlan brief"),
    ]:
        mock_connection = Mock()
        mock_connection.send_command.side_effect = RuntimeError(
            "Simulated command failure"
        )

        with patch(
            "backend.app.services.cisco_readonly.connect_readonly",
            return_value=mock_connection,
        ):
            try:
                function("192.0.2.10")
            except RuntimeError as exc:
                assert str(exc) == "Simulated command failure"
            else:
                raise AssertionError("Expected RuntimeError was not raised")

        mock_connection.send_command.assert_called_once_with(
            command,
            read_timeout=30,
        )
        mock_connection.disconnect.assert_called_once_with()

def test_connect_readonly_rejects_missing_credentials():
    from unittest.mock import patch

    from backend.app.services.cisco_readonly import (
        connect_readonly,
    )

    with (
        patch.dict(
            "os.environ",
            {"NETOPS_SWITCH_ALLOWED_IPS": "192.0.2.10"},
            clear=True,
        ),
        patch(
            "backend.app.services.cisco_readonly.ConnectHandler"
        ) as mock_connect,
    ):
        try:
            connect_readonly("192.0.2.10")
        except RuntimeError as exc:
            assert "Cisco credentials are not configured" in str(exc)
        else:
            raise AssertionError("Expected RuntimeError was not raised")

    mock_connect.assert_not_called()


def test_connect_readonly_rejects_invalid_management_ip():
    from unittest.mock import patch

    from backend.app.services.cisco_readonly import connect_readonly

    with (
        patch.dict(
            "os.environ",
            {
                "NETOPS_SWITCH_USERNAME": "test-user",
                "NETOPS_SWITCH_PASSWORD": "test-password",
            },
        ),
        patch(
            "backend.app.services.cisco_readonly.ConnectHandler"
        ) as mock_connect,
    ):
        try:
            connect_readonly("not-an-ip-address")
        except ValueError as exc:
            assert str(exc) == (
                "A valid switch management IP address is required."
            )
        else:
            raise AssertionError("Expected ValueError was not raised")

    mock_connect.assert_not_called()


def test_connect_readonly_accepts_valid_ip_format():
    from unittest.mock import Mock, patch

    from backend.app.services.cisco_readonly import connect_readonly

    mock_connection = Mock()

    with (
        patch.dict(
            "os.environ",
            {
                "NETOPS_SWITCH_USERNAME": "test-user",
                "NETOPS_SWITCH_PASSWORD": "test-password",
                "NETOPS_SWITCH_ALLOWED_IPS": "192.0.2.10",
            },
        ),
        patch(
            "backend.app.services.cisco_readonly.ConnectHandler",
            return_value=mock_connection,
        ) as mock_connect,
    ):
        result = connect_readonly("192.0.2.10")

    assert result is mock_connection
    mock_connect.assert_called_once()
    assert mock_connect.call_args.kwargs["host"] == "192.0.2.10"

def test_connect_readonly_rejects_unapproved_management_ip():
    from unittest.mock import patch

    from backend.app.services.cisco_readonly import connect_readonly

    with (
        patch.dict(
            "os.environ",
            {
                "NETOPS_SWITCH_USERNAME": "test-user",
                "NETOPS_SWITCH_PASSWORD": "test-password",
                "NETOPS_SWITCH_ALLOWED_IPS": "192.0.2.20",
            },
        ),
        patch(
            "backend.app.services.cisco_readonly.ConnectHandler"
        ) as mock_connect,
    ):
        try:
            connect_readonly("192.0.2.10")
        except PermissionError as exc:
            assert str(exc) == (
                "Switch management IP is not on the approved list."
            )
        else:
            raise AssertionError("Expected PermissionError was not raised")

    mock_connect.assert_not_called()


def test_connect_readonly_allows_listed_management_ip():
    from unittest.mock import Mock, patch

    from backend.app.services.cisco_readonly import connect_readonly

    mock_connection = Mock()

    with (
        patch.dict(
            "os.environ",
            {
                "NETOPS_SWITCH_USERNAME": "test-user",
                "NETOPS_SWITCH_PASSWORD": "test-password",
                "NETOPS_SWITCH_ALLOWED_IPS": "192.0.2.10",
            },
        ),
        patch(
            "backend.app.services.cisco_readonly.ConnectHandler",
            return_value=mock_connection,
        ) as mock_connect,
    ):
        result = connect_readonly("192.0.2.10")

    assert result is mock_connection
    mock_connect.assert_called_once()
    assert mock_connect.call_args.kwargs["host"] == "192.0.2.10"
