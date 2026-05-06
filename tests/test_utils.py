# Standard Python Libraries
from pathlib import Path
from unittest.mock import MagicMock, call, patch

# Third-Party Libraries
import numpy as np
import pandas as pd
import pytest

# cisagov Libraries
from app.utils.utils import (
    FilePathInfo,
    PortType,
    _normalize_categories,
    check_ip_version,
    connection_type_processing,
    convert_list_col_to_str,
    count_values_in_list_column,
    is_communicating_with_ot_hosts,
    is_public_ip,
    is_using_ot_services,
    service_processing,
    set_manufacturers,
    subnet_membership,
    traffic_direction,
)

# --- Test _normalize_categories ---


@pytest.mark.parametrize(
    "input_categories, expected_output",
    [
        (["Cat1", "Cat2"], "Cat1, Cat2"),
        (np.array(["CatA", "CatB"]), "CatA, CatB"),
        (["Cat1", None, "Cat2"], "Cat1, Cat2"),
        (["Cat1", np.nan, "Cat2"], "Cat1, Cat2"),
        (["Cat1", "", "Cat2"], "Cat1, Cat2"),
        ([], None),
        (np.array([]), None),
        (None, None),
        (np.nan, None),
        ("SingleCat", "SingleCat"),
        ("", None),
        ("  ", None),
        (123, "123"),  # Non-string input
    ],
)
def test_normalize_categories(input_categories, expected_output):
    assert _normalize_categories(input_categories) == expected_output


# --- Test FilePathInfo ---


@patch("app.utils.utils.os.mkdir")
@patch("app.utils.utils.Path.exists", return_value=False)
def test_filepath_info_creates_directories(mock_exists, mock_mkdir):
    pcap_dir = "/tmp/pcap_dir"
    zeek_dir = "/tmp/zeek_output"
    zeek_scripts_dir = "/tmp/zeek_scripts"
    assessor_data_dir = "/tmp/assessor_data"

    # Mock Path.parent.exists for pcap_dir
    with patch(
        "app.utils.utils.Path.parent", new_callable=MagicMock
    ) as mock_path_parent:
        mock_path_parent.exists.return_value = False

        FilePathInfo(
            path_to_pcap=f"{pcap_dir}/test.pcap",
            path_to_zeek=zeek_dir,
            path_to_zeek_scripts=zeek_scripts_dir,
            path_to_assessor_data=assessor_data_dir,
        )

        expected_calls = [
            call(zeek_dir),
            call(zeek_scripts_dir),
            call(assessor_data_dir),
            call(Path(pcap_dir)),  # For the parent of pcap_path
        ]
        # Check that mkdir was called for each unique directory
        mock_mkdir.assert_has_calls(expected_calls, any_order=True)
        assert mock_mkdir.call_count == 4


# --- Test IP Processing Functions ---


@pytest.mark.parametrize(
    "ip_str, expected",
    [
        ("8.8.8.8", True),
        ("2001:4860:4860::8888", True),
        ("192.168.1.1", False),
        ("10.0.0.1", False),
        ("172.16.0.1", False),
        ("127.0.0.1", False),
        ("fe80::1", False),
        ("invalid-ip", False),
        (None, False),
        (123, False),
    ],
)
def test_is_public_ip(ip_str, expected):
    assert is_public_ip(ip_str) == expected


@pytest.mark.parametrize(
    "ip_str, expected",
    [
        ("192.168.1.1", 4),
        ("10.0.0.1", 4),
        ("8.8.8.8", 4),
        ("fe80::1", 6),
        ("2001:db8::1", 6),
        ("invalid-ip", 99),
        (None, 99),
        (123, 99),
    ],
)
def test_check_ip_version(ip_str, expected):
    assert check_ip_version(ip_str) == expected


@pytest.mark.parametrize(
    "ip_str, expected",
    [
        ("224.0.0.1", "multicast"),
        ("ff02::1", "multicast"),
        ("169.254.0.1", "link-local"),
        ("fe80::1", "link-local"),
        ("255.255.255.255", "broadcast"),
        ("192.168.1.1", "unicast"),
        ("8.8.8.8", "unicast"),
        ("invalid-ip", None),
        (None, None),
    ],
)
def test_connection_type_processing(ip_str, expected):
    assert connection_type_processing(ip_str) == expected


@pytest.mark.parametrize(
    "src_ip, dst_ip, expected",
    [
        ("192.168.1.1", "192.168.1.10", "lateral"),
        ("10.0.0.1", "172.16.0.1", "lateral"),
        ("192.168.1.1", "8.8.8.8", "outbound"),
        (
            "fe80::1",
            "2001:db8::1",
            "lateral",
        ),
        ("8.8.8.8", "192.168.1.1", "inbound"),
        ("2001:db8::1", "fe80::1", "lateral"),
        ("8.8.8.8", "4.4.4.4", "external"),
        ("2001:db8::1", "2001:db8::2", "lateral"),
        ("invalid-src", "192.168.1.1", None),
        ("192.168.1.1", "invalid-dst", None),
        (
            "192.168.1.1",
            "224.0.0.1",
            "lateral",
        ),
        ("192.168.1.1", "ff02::1", "lateral"),
    ],
)
def test_traffic_direction(src_ip, dst_ip, expected):
    row = pd.Series({"src_endpoint.ip": src_ip, "dst_endpoint.ip": dst_ip})
    assert traffic_direction(row) == expected


@pytest.mark.parametrize(
    "src_ip, dst_ip, protocol_ver_id, expected_src_subnet, expected_dst_subnet",
    [
        # IPv4
        ("192.168.1.10", "192.168.1.1", 4, "192.168.1.0/24", "192.168.1.0/24"),
        ("10.0.0.5", "8.8.8.8", 4, "10.0.0.0/24", "8.8.8.0/24"),
        ("0.0.0.0", "192.168.1.1", 4, None, "192.168.1.0/24"),
        ("192.168.1.10", "0.0.0.0", 4, "192.168.1.0/24", None),
        ("192.168.1.10", "255.255.255.255", 4, "192.168.1.0/24", "192.168.1.0/24"),
        # IPv6
        ("fe80::1", "fe80::10", 6, "fe80::/64", "fe80::/64"),
        ("2001:db8::1", "2001:db8::10", 6, "2001:db8::/64", "2001:db8::/64"),
        ("::", "2001:db8::1", 6, None, "2001:db8::/64"),
        ("2001:db8::1", "::", 6, "2001:db8::/64", None),
        # Mixed/Invalid
        ("invalid-ip", "192.168.1.1", 4, None, "192.168.1.0/24"),
        ("192.168.1.1", "invalid-ip", 4, "192.168.1.0/24", None),
        ("192.168.1.1", "192.168.1.10", 99, None, None),  # Invalid protocol_ver_id
    ],
)
def test_subnet_membership(
    src_ip, dst_ip, protocol_ver_id, expected_src_subnet, expected_dst_subnet
):
    row = pd.Series(
        {
            "src_endpoint.ip": src_ip,
            "dst_endpoint.ip": dst_ip,
            "connection_info.protocol_ver_id": protocol_ver_id,
        }
    )
    result_row = subnet_membership(row)
    assert result_row["src_endpoint.subnet"] == expected_src_subnet
    assert result_row["dst_endpoint.subnet"] == expected_dst_subnet


# --- Test Service Processing Functions ---


@pytest.fixture
def mock_ports_df():
    return pd.DataFrame(
        {
            "port": [80, 443, 22],
            "Service Name": ["HTTP", "HTTPS", "SSH"],
            "OT System Type": [False, False, True],
        }
    )


@pytest.fixture
def mock_port_risk_df():
    return pd.DataFrame(
        {
            "port": [80, 443, 21, 53],
            "service": ["HTTP", "HTTPS", "FTP", "DNS"],
            "description": [
                "Web traffic",
                "Secure Web",
                "File Transfer",
                "Domain Name",
            ],
            "information_categories": [["Web"], ["Web", "Secure"], ["File"], ["DNS"]],
            "risk_categories": [["Low"], ["Medium"], ["High"], ["Low"]],
            "risk_basis": ["Observed", "Credible", "Observed", "Observed"],
            "environment_exposure": ["Internal", "External", "Internal", "Internal"],
            "protocol_posture": [
                "Conditionally Risky",
                "Inherently Risky",
                "Inherently Risky",
                "Conditionally Risky",
            ],
        }
    )


@pytest.mark.parametrize(
    "port, expected_service_name, expected_port_type, expected_risk_categories",
    [
        # Known port, in both ports_df and port_risk_df (port_risk_df should take precedence for service name and details)
        (80, "HTTP", PortType.KNOWN.name, "Low"),
        # Known port, in ports_df only (should get name from ports_df, no risk info)
        (22, "SSH", PortType.KNOWN.name, None),
        # Known port, in port_risk_df only (should get name and risk from port_risk_df)
        (21, "FTP", PortType.KNOWN.name, "High"),
        # Unknown privileged port
        (
            23,
            "UNKNOWN_PRIV 23",
            PortType.UNKNOWN_PRIV.name,
            "Legacy Protocol, Unknown Service",
        ),
        # Unknown port
        (12345, "UNKNOWN 12345", PortType.UNKNOWN.name, "Unknown Service"),
        # Ephemeral port
        (50000, "EPHEMERAL 50000", PortType.EPHEMERAL.name, None),
    ],
)
def test_service_processing(
    port,
    expected_service_name,
    expected_port_type,
    expected_risk_categories,
    mock_ports_df,
    mock_port_risk_df,
):
    row = pd.Series({"dst_endpoint.port": port})
    result_row = service_processing(row, mock_ports_df, mock_port_risk_df)

    assert result_row["service.name"] == expected_service_name
    assert result_row["service.port_type"] == expected_port_type

    # Normalize expected_risk_categories for comparison
    normalized_expected_risk = (
        _normalize_categories(expected_risk_categories.split(", "))
        if expected_risk_categories
        else None
    )
    assert result_row["service.risk_categories"] == normalized_expected_risk

    # Check default values for other fields if not explicitly set by port_risk_df
    if (
        expected_port_type == PortType.KNOWN.name
        and port in mock_port_risk_df["port"].values
    ):
        # If from port_risk_df, check specific fields
        pr_row = mock_port_risk_df[mock_port_risk_df["port"] == port].iloc[0]
        assert result_row["service.description"] == pr_row["description"]
        assert result_row["service.information_categories"] == _normalize_categories(
            pr_row["information_categories"]
        )
    elif (
        expected_port_type == PortType.KNOWN.name
        and port in mock_ports_df["port"].values
    ):
        # If from ports_df only, description and categories should be None
        assert result_row["service.description"] is None
        assert result_row["service.information_categories"] is None
    else:
        # For unknown/ephemeral, check specific descriptions
        if expected_port_type == PortType.UNKNOWN_PRIV.name:
            assert (
                "Unassigned well-known port number" in result_row["service.description"]
            )
        elif expected_port_type == PortType.UNKNOWN.name:
            assert "Unknown assigned port" in result_row["service.description"]
        elif expected_port_type == PortType.EPHEMERAL.name:
            assert "EPHEMERAL" in result_row["service.description"]


def test_service_processing_port_risk_no_service_name_raises_error(mock_ports_df):
    # Create a port_risk_df entry that has no 'service' name
    port_risk_df_no_service = pd.DataFrame(
        {
            "port": [9999],
            "service": [np.nan],  # No service name
            "description": ["Test"],
            "information_categories": [["Test"]],
            "risk_categories": [["Test"]],
            "risk_basis": ["Observed"],
            "environment_exposure": ["Internal"],
            "protocol_posture": ["Conditionally Risky"],
        }
    )
    row = pd.Series({"dst_endpoint.port": 9999})
    with pytest.raises(
        ValueError, match="Port 9999 does not have a service name defined!"
    ):
        service_processing(row, mock_ports_df, port_risk_df_no_service)


# --- Test Endpoint Processing Functions ---


@pytest.fixture
def mock_manufacturers_df():
    return pd.DataFrame(
        {"manufacturer": ["Test Mfg A", "Test Mfg B"]},
        index=pd.Index(["AA-AA-AA", "BB-BB-BB"], name="oui"),
    )


@pytest.mark.parametrize(
    "mac, expected_manufacturer",
    [
        ("AA:AA:AA:AA:AA:AA", "Test Mfg A"),
        ("BB:BB:BB:BB:BB:BB", "Test Mfg B"),
        ("CC:CC:CC:CC:CC:CC", None),  # Not found
        ("", None),  # Empty MAC
        (None, None),  # None MAC
        (123, None),  # Non-string MAC
    ],
)
def test_set_manufacturers(mac, expected_manufacturer, mock_manufacturers_df):
    row = pd.Series({"device.mac": mac, "device.manufacturer": None}, dtype=object)
    result_row = set_manufacturers(row, mock_manufacturers_df)
    assert result_row["device.manufacturer"] == expected_manufacturer


@pytest.fixture
def sample_traffic_df():
    return pd.DataFrame(
        {
            "src_endpoint.ip": ["192.168.1.1", "192.168.1.2", "10.0.0.1", "10.0.0.2"],
            "dst_endpoint.ip": [
                "192.168.1.10",
                "10.0.0.10",
                "10.0.0.20",
                "192.168.1.20",
            ],
            "service.is_ot": [
                False,
                True,
                False,
                True,
            ],  # Service from 192.168.1.2 and 10.0.0.2 is OT
        }
    )


@pytest.mark.parametrize(
    "ipv4_ips, ipv6_ips, expected_is_ot",
    [
        (["192.168.1.1"], [], False),  # No OT service for this IP
        (["192.168.1.2"], [], True),  # Uses OT service
        ([], ["fe80::1"], False),  # No traffic for this IPv6
        (["10.0.0.1"], ["fe80::2"], False),  # No OT service for these IPs
        ([], [], False),  # No IPs
        (None, None, False),  # No IPs
    ],
)
def test_is_using_ot_services(ipv4_ips, ipv6_ips, expected_is_ot, sample_traffic_df):
    row = pd.Series({"device.ipv4_ips": ipv4_ips, "device.ipv6_ips": ipv6_ips})
    assert is_using_ot_services(row, sample_traffic_df) == expected_is_ot


@pytest.mark.parametrize(
    "device_is_ot, device_ipv4_ips, device_ipv6_ips, ot_ips, expected_is_ot_after_check",
    [
        (
            True,
            ["192.168.1.1"],
            [],
            {"10.0.0.10"},
            True,
        ),  # Already OT, should remain OT
        (
            False,
            ["192.168.1.1"],
            [],
            {"10.0.0.10"},
            False,
        ),  # Not OT, no communication with OT
        (
            False,
            ["192.168.1.1"],
            [],
            {"192.168.1.10"},
            True,
        ),  # Not OT, communicates with OT
        # Not OT, communicates with OT
        (False, ["10.0.0.1"], [], {"10.0.0.20"}, True),
        (False, [], [], {"10.0.0.10"}, False),  # No IPs for device
        (False, None, None, {"10.0.0.10"}, False),  # No IPs for device
    ],
)
def test_is_communicating_with_ot_hosts(
    device_is_ot,
    device_ipv4_ips,
    device_ipv6_ips,
    ot_ips,
    expected_is_ot_after_check,
    sample_traffic_df,
):
    row = pd.Series(
        {
            "device.is_ot": device_is_ot,
            "device.ipv4_ips": device_ipv4_ips,
            "device.ipv6_ips": device_ipv6_ips,
        }
    )
    result_row = is_communicating_with_ot_hosts(row, sample_traffic_df, ot_ips)
    assert result_row["device.is_ot"] == expected_is_ot_after_check


# --- Test Data Manipulation Functions ---


@pytest.mark.parametrize(
    "input_value, expected_output",
    [
        (["item1", "item2"], "item1, item2"),
        (["single_item"], "single_item"),
        ([], []),  # Empty list should remain empty list
        ("not_a_list", "not_a_list"),  # Non-list should remain unchanged
        (None, None),
    ],
)
def test_convert_list_col_to_str(input_value, expected_output):
    row = pd.Series({"test_column": input_value})
    result_row = convert_list_col_to_str(row, "test_column")
    assert result_row["test_column"] == expected_output


@pytest.mark.parametrize(
    "data, column_name, expected_counts",
    [
        (pd.DataFrame({"col": ["A, B", "A", "C, B"]}), "col", {"A": 2, "B": 2, "C": 1}),
        (pd.DataFrame({"col": ["A"]}), "col", {"A": 1}),
        (
            pd.DataFrame({"col": ["A, A"]}),
            "col",
            {"A": 2},
        ),  # Should count each occurrence
        (pd.DataFrame({"col": ["A, B", None, "C"]}), "col", {"A": 1, "B": 1, "C": 1}),
        (pd.DataFrame({"col": ["A, B", np.nan, "C"]}), "col", {"A": 1, "B": 1, "C": 1}),
        (pd.DataFrame({"col": ["A, B", "", "C"]}), "col", {"A": 1, "B": 1, "C": 1}),
        (pd.DataFrame({"col": []}), "col", {}),  # Empty DataFrame
        (
            pd.DataFrame({"col": [None, np.nan, ""]}),
            "col",
            {},
        ),  # DataFrame with only empty/null values
    ],
)
def test_count_values_in_list_column(data, column_name, expected_counts):
    assert count_values_in_list_column(data, column_name) == expected_counts
