elevadr - web - backend - bailey - dev / tests / test_analysis.py
# Standard Python Libraries
import json
from pathlib import Path
from unittest.mock import MagicMock, call, patch

# Third-Party Libraries
import numpy as np
import pandas as pd
import pytest

# cisagov Libraries
from src.app.utils.analysis import Analyzer, PcapParser
from src.app.utils.utils import FilePathInfo, PortType


# Fixture for FilePathInfo
@pytest.fixture
def mock_file_path_info():
    return FilePathInfo(
        path_to_pcap="/tmp/test.pcap",
        path_to_zeek="/tmp/zeek_output",
        path_to_zeek_scripts="/tmp/zeek_scripts",
        path_to_assessor_data="/tmp/assessor_data",
    )


# Fixture for a dummy traffic_df
@pytest.fixture
def dummy_traffic_df():
    data = {
        "connection_info.protocol_ver_id": [4, 4, 6],
        "connection_info.type_name": ["unicast", "unicast", "unicast"],
        "connection_info.direction_name": ["inbound", "outbound", "lateral"],
        "connection_info.protocol_name": ["tcp", "udp", "tcp"],
        "connection_info.activity_name": ["S0", "S1", "S0"],
        "dst_endpoint.ip": ["192.168.1.10", "10.0.0.5", "fe80::1"],
        "dst_endpoint.mac": [
            "00:00:00:00:00:01",
            "00:00:00:00:00:02",
            "00:00:00:00:00:03",
        ],
        "dst_endpoint.port": [80, 53, 443],
        "dst_endpoint.subnet": ["192.168.1.0/24", "10.0.0.0/8", "fe80::/64"],
        "src_endpoint.ip": ["192.168.1.1", "10.0.0.1", "fe80::2"],
        "src_endpoint.mac": [
            "00:00:00:00:00:04",
            "00:00:00:00:00:05",
            "00:00:00:00:00:06",
        ],
        "src_endpoint.port": [12345, 54321, 67890],
        "src_endpoint.subnet": ["192.168.1.0/24", "10.0.0.0/8", "fe80::/64"],
        "service.name": ["HTTP", "DNS", "HTTPS"],
        "service.port_type": [
            PortType.KNOWN.name,
            PortType.KNOWN.name,
            PortType.KNOWN.name,
        ],
        "service.description": [
            "Web traffic",
            "Domain Name System",
            "Secure Web traffic",
        ],
        "service.information_categories": ["Web", "DNS", "Web"],
        "service.risk_categories": ["Low", "Low", "Medium"],
        "service.risk_basis": ["Observed", "Observed", "Credible"],
        "service.environment_exposure": ["Internal", "Internal", "External"],
        "service.protocol_posture": [
            "Conditionally Risky",
            "Conditionally Risky",
            "Inherently Risky",
        ],
        "service.is_ot": [False, False, False],
    }
    return pd.DataFrame(data)


# Fixture for a dummy endpoints_df
@pytest.fixture
def dummy_endpoints_df():
    data = {
        "device.mac": ["00:00:00:00:00:01", "00:00:00:00:00:02"],
        "device.manufacturer": ["Manufacturer A", "Manufacturer B"],
        "device.is_ot": [True, False],
        "device.is_edge": [False, True],
        "device.ipv4_ips": [["192.168.1.10"], ["10.0.0.5"]],
        "device.ipv6_ips": [np.nan, np.nan],
        "device.ip_scope": ["private", "private"],
        "device.ipv4_subnets": [["192.168.1.0/24"], ["10.0.0.0/8"]],
        "device.ipv6_subnets": [np.nan, np.nan],
        "device.protocol_ver_id": [4, 4],
        "device.sent_services": [set(), {"DNS"}],
        "device.incoming_services": [{"HTTP"}, set()],
        "device.sent_ports": [set(), {53}],
        "device.incoming_ports": [{80}, set()],
    }
    return pd.DataFrame(data).set_index("device.mac")


# Fixture for a dummy services_df
@pytest.fixture
def dummy_services_df():
    data = {
        "service.name": ["HTTP", "DNS"],
        "service.port_type": [PortType.KNOWN.name, PortType.KNOWN.name],
        "service.description": ["Web traffic", "Domain Name System"],
        "service.information_categories": ["Web", "DNS"],
        "service.risk_categories": ["Low", "Low"],
        "service.risk_basis": ["Observed", "Observed"],
        "service.environment_exposure": ["Internal", "Internal"],
        "service.protocol_posture": ["Conditionally Risky", "Conditionally Risky"],
        "service.is_ot": [False, False],
    }
    return pd.DataFrame(data)


class TestPcapParser:
    @patch("src.app.utils.analysis.subprocess.check_output")
    @patch("src.app.utils.analysis.Path.mkdir")
    def test_zeekify(self, mock_mkdir, mock_check_output, mock_file_path_info):
        parser = PcapParser(mock_file_path_info)
        parser.zeekify()

        mock_mkdir.assert_called_once_with(parents=True)

        # Check calls for default Zeek processing
        mock_check_output.assert_any_call(
            [
                "zeek",
                "-r",
                mock_file_path_info.path_to_pcap,
                f"Log::default_logdir={parser.upload_output_zeek_dir}",
            ]
        )

        # Check calls for mac_logging Zeek script
        mac_script_path = (
            Path(mock_file_path_info.path_to_zeek_scripts) / "mac_logging.zeek"
        )
        mock_check_output.assert_any_call(
            [
                "zeek",
                "-r",
                mock_file_path_info.path_to_pcap,
                str(mac_script_path),
                f"Log::default_logdir={parser.upload_output_zeek_dir}",
            ]
        )
        assert mock_check_output.call_count == 2

    @patch("src.app.utils.analysis.LogToDataFrame")
    @patch("src.app.utils.analysis.PcapParser.zeekify")
    @patch("src.app.utils.analysis.Path.exists", return_value=True)
    def test_pcap_parser_init(
        self, mock_path_exists, mock_zeekify, MockLogToDataFrame, mock_file_path_info
    ):
        # Mock LogToDataFrame to return a dummy DataFrame for conn.log
        mock_log_to_df_instance = MockLogToDataFrame.return_value
        mock_log_to_df_instance.create_dataframe.return_value = pd.DataFrame(
            {
                "proto": ["tcp", "udp"],
                "id.orig_h": ["192.168.1.1", "10.0.0.1"],
                "id.orig_p": [12345, 54321],
                "id.resp_h": ["192.168.1.10", "10.0.0.5"],
                "id.resp_p": [80, 53],
                "orig_l2_addr": ["00:00:00:00:00:04", "00:00:00:00:00:05"],
                "resp_l2_addr": ["00:00:00:00:00:01", "00:00:00:00:00:02"],
                "conn_state": ["S0", "S1"],
            }
        )

        parser = PcapParser(mock_file_path_info)

        mock_zeekify.assert_called_once()
        MockLogToDataFrame.assert_called_once()
        mock_log_to_df_instance.create_dataframe.assert_called_once()

        assert not parser.traffic_df.empty
        assert "connection_info.protocol_name" in parser.traffic_df.columns
        assert "src_endpoint.ip" in parser.traffic_df.columns
        assert "dst_endpoint.port" in parser.traffic_df.columns
        assert parser.endpoints_df.empty
        assert parser.services_df.empty


class TestAnalyzer:
    @pytest.mark.parametrize(
        "ip_value, expected",
        [
            ("169.254.0.1", True),  # Link-local IPv4
            ("fe80::1", True),  # Link-local IPv6
            ("224.0.0.1", True),  # Multicast IPv4
            ("ff00::1", True),  # Multicast IPv6
            ("255.255.255.255", True),  # IPv4 Broadcast
            ("192.168.1.1", False),  # Private IPv4
            ("8.8.8.8", False),  # Public IPv4
            ("2001:db8::1", False),  # Public IPv6
            ("invalid-ip", False),  # Invalid IP
            (None, False),  # None
            ("", False),  # Empty string
            (123, False),  # Non-string
        ],
    )
    def test_is_excluded_cross_segment_ip(self, ip_value, expected):
        # Analyzer constructor calls other methods, mock them to isolate _is_excluded_cross_segment_ip
        with (
            patch("src.app.utils.analysis.Analyzer.get_assessor_data"),
            patch("src.app.utils.analysis.Analyzer.traffic_df_processing"),
            patch("src.app.utils.analysis.Analyzer.endpoints_df_processing"),
            patch("src.app.utils.analysis.Analyzer.services_df_processing"),
        ):
            analyzer = Analyzer(
                pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), MagicMock()
            )
            assert analyzer._is_excluded_cross_segment_ip(ip_value) == expected

    @patch("src.app.utils.analysis.pd.read_parquet")
    @patch("builtins.open", new_callable=MagicMock)
    @patch("json.load")
    @patch("src.app.utils.analysis.Analyzer.traffic_df_processing")
    @patch("src.app.utils.analysis.Analyzer.endpoints_df_processing")
    @patch("src.app.utils.analysis.Analyzer.services_df_processing")
    def test_get_assessor_data(
        self,
        mock_services_df_processing,
        mock_endpoints_df_processing,
        mock_traffic_df_processing,
        mock_json_load,
        mock_open,
        mock_read_parquet,
        mock_file_path_info,
    ):
        # Mock return values for parquet and json files
        mock_read_parquet.side_effect = [
            pd.DataFrame({"port": [80, 443]}),  # ports_df
            pd.DataFrame({"port": [80], "risk": ["low"]}),  # port_risk_df
        ]
        mock_json_load.return_value = {"000000": "Test Manufacturer"}

        analyzer = Analyzer(
            pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), mock_file_path_info
        )
        # __init__ calls get_assessor_data, so we don't need to call it explicitly

        assert hasattr(analyzer, "ports_df")
        assert not analyzer.ports_df.empty
        assert hasattr(analyzer, "port_risk_df")
        assert not analyzer.port_risk_df.empty
        assert hasattr(analyzer, "manufacturers_df")
        assert not analyzer.manufacturers_df.empty

        mock_read_parquet.assert_has_calls(
            [
                call(
                    Path(mock_file_path_info.path_to_assessor_data) / "ports.parquet",
                    engine="pyarrow",
                ),
                call(
                    Path(mock_file_path_info.path_to_assessor_data)
                    / "port_risk_v2.parquet",
                    engine="pyarrow",
                ),
            ]
        )
        mock_open.assert_called_once_with(
            Path(mock_file_path_info.path_to_assessor_data) / "latest_oui_lookup.json",
            "r",
        )
        mock_json_load.assert_called_once()

        # Check manufacturer_df processing
        assert analyzer.manufacturers_df.index.name == "oui"
        assert "manufacturer" in analyzer.manufacturers_df.columns

    @patch(
        "src.app.utils.analysis.check_ip_version",
        side_effect=lambda ip: 4 if ip.startswith("192") else 6,
    )
    @patch("src.app.utils.analysis.connection_type_processing", return_value="unicast")
    @patch("src.app.utils.analysis.traffic_direction", return_value="inbound")
    @patch("src.app.utils.analysis.subnet_membership", side_effect=lambda row: row)
    @patch(
        "src.app.utils.analysis.service_processing",
        side_effect=lambda row, ports_df, port_risk_df: row,
    )
    @patch("src.app.utils.analysis.Analyzer.get_assessor_data")
    @patch("src.app.utils.analysis.Analyzer.endpoints_df_processing")
    @patch("src.app.utils.analysis.Analyzer.services_df_processing")
    def test_traffic_df_processing(
        self,
        mock_services_df_processing,
        mock_endpoints_df_processing,
        mock_get_assessor_data,
        mock_service_processing,
        mock_subnet_membership,
        mock_traffic_direction,
        mock_connection_type_processing,
        mock_check_ip_version,
        dummy_traffic_df,
    ):
        analyzer = Analyzer(
            dummy_traffic_df.copy(), pd.DataFrame(), pd.DataFrame(), MagicMock()
        )
        # __init__ calls traffic_df_processing, so we don't need to call it explicitly
        # Instead, we call it explicitly after setting up the mocks
        analyzer.traffic_df_processing()

        mock_check_ip_version.assert_called()
        mock_connection_type_processing.assert_called()
        mock_traffic_direction.assert_called()
        mock_subnet_membership.assert_called()
        mock_service_processing.assert_called()

        # Verify that the columns were added/modified
        assert "connection_info.protocol_ver_id" in analyzer.traffic_df.columns
        assert "connection_info.type_name" in analyzer.traffic_df.columns
        assert "connection_info.direction_name" in analyzer.traffic_df.columns

    @patch("src.app.utils.analysis.Analyzer.get_assessor_data")
    @patch("src.app.utils.analysis.Analyzer.traffic_df_processing")
    @patch("src.app.utils.analysis.Analyzer.endpoints_df_processing")
    @patch("src.app.utils.analysis.Analyzer.services_df_processing")
    def test_service_counts_in_traffic(
        self,
        mock_services_df_processing,
        mock_endpoints_df_processing,
        mock_traffic_df_processing,
        mock_get_assessor_data,
    ):
        # Create a dummy traffic_df for service counting
        traffic_data = {
            "service.name": [
                "HTTP",
                "DNS",
                "HTTP",
                "UNKNOWN_SERVICE_12345",
                "UNKNOWN_SERVICE_54321",
                "HTTP",
            ],
            "service.port_type": [
                PortType.KNOWN.name,
                PortType.KNOWN.name,
                PortType.KNOWN.name,
                PortType.UNKNOWN.name,
                PortType.EPHEMERAL.name,
                PortType.KNOWN.name,
            ],
            "dst_endpoint.port": [80, 53, 80, 12345, 54321, 8080],
        }
        traffic_df = pd.DataFrame(traffic_data)

        analyzer = Analyzer(traffic_df, pd.DataFrame(), pd.DataFrame(), MagicMock())
        analyzer.traffic_df = (
            traffic_df  # Ensure the traffic_df is the one we want to test with
        )
        result = analyzer.service_counts_in_traffic()

        expected_known_services = [
            {"name": "HTTP", "port": 80, "count": 2},
            {"name": "HTTP", "port": 8080, "count": 1},
            {"name": "DNS", "port": 53, "count": 1},
        ]
        # Sort both lists of dicts for comparison
        assert sorted(
            result["known_services"], key=lambda x: (x["name"], x["port"])
        ) == sorted(expected_known_services, key=lambda x: (x["name"], x["port"]))
        assert result["unknown_services"] == {
            "UNKNOWN_SERVICE_12345": 1,
            "UNKNOWN_SERVICE_54321": 1,
        }

    @patch("src.app.utils.analysis.Analyzer.get_assessor_data")
    @patch("src.app.utils.analysis.Analyzer.traffic_df_processing")
    @patch("src.app.utils.analysis.Analyzer.endpoints_df_processing")
    @patch("src.app.utils.analysis.Analyzer.services_df_processing")
    def test_service_category_map(
        self,
        mock_services_df_processing,
        mock_endpoints_df_processing,
        mock_traffic_df_processing,
        mock_get_assessor_data,
    ):
        # Create a dummy services_df for category mapping
        services_data = {
            "service.name": ["ServiceA", "ServiceB", "ServiceC", "ServiceD"],
            "service.information_categories": ["Cat1, Cat2", "Cat2", "Cat3", None],
            "service.risk_categories": ["RiskA", "RiskB, RiskC", None, "RiskD"],
        }
        services_df = pd.DataFrame(services_data)

        analyzer = Analyzer(pd.DataFrame(), pd.DataFrame(), services_df, MagicMock())
        analyzer.services_df = (
            services_df  # Ensure the services_df is the one we want to test with
        )

        info_map = analyzer.service_category_map("service.information_categories")
        risk_map = analyzer.service_category_map("service.risk_categories")

        assert info_map == {"Cat1": ["ServiceA"], "Cat2": ["ServiceA", "ServiceB"]}
        assert risk_map == {
            "RiskA": ["ServiceA"],
            "RiskB": ["ServiceB"],
            "RiskC": ["ServiceB"],
            "RiskD": ["ServiceD"],
        }

        # Test with empty categories
        services_df_empty_cat = pd.DataFrame(
            {
                "service.name": ["ServiceE"],
                "service.information_categories": [""],
                "service.risk_categories": ["RiskE"],
            }
        )
        analyzer_empty_cat = Analyzer(
            pd.DataFrame(), pd.DataFrame(), services_df_empty_cat, MagicMock()
        )
        analyzer_empty_cat.services_df = services_df_empty_cat
        info_map_empty = analyzer_empty_cat.service_category_map(
            "service.information_categories"
        )
        assert info_map_empty == {}

    @patch("src.app.utils.analysis.set_manufacturers", side_effect=lambda row, df: row)
    @patch("src.app.utils.analysis.is_using_ot_services", return_value=False)
    @patch(
        "src.app.utils.analysis.is_communicating_with_ot_hosts",
        side_effect=lambda row, traffic_df, ot_ips: row,
    )
    @patch("src.app.utils.analysis.is_public_ip", return_value=False)
    @patch(
        "src.app.utils.analysis.check_ip_version",
        side_effect=lambda ip: 4 if ip.startswith("192") else 6,
    )
    @patch("src.app.utils.analysis.Analyzer.get_assessor_data")
    @patch("src.app.utils.analysis.Analyzer.traffic_df_processing")
    @patch("src.app.utils.analysis.Analyzer.services_df_processing")
    def test_endpoints_df_processing(
        self,
        mock_services_df_processing,
        mock_traffic_df_processing,
        mock_get_assessor_data,
        mock_check_ip_version,
        mock_is_public_ip,
        mock_is_communicating_with_ot_hosts,
        mock_is_using_ot_services,
        mock_set_manufacturers,
        mock_file_path_info,
    ):
        # Setup a traffic_df that will result in distinct endpoints
        traffic_data = {
            "connection_info.type_name": [
                "unicast",
                "unicast",
                "unicast",
                "unicast",
                "unicast",
                "unicast",
                "unicast",
            ],
            "src_endpoint.ip": [
                "192.168.1.1",
                "192.168.1.2",
                "10.0.0.1",
                "192.168.1.1",
                "0.0.0.0",
                "::",
                "192.168.1.3",
            ],
            "src_endpoint.mac": [
                "AA:AA:AA:AA:AA:AA",
                "BB:BB:BB:BB:BB:BB",
                "CC:CC:CC:CC:CC:CC",
                "AA:AA:AA:AA:AA:AA",
                "XX:XX:XX:XX:XX:XX",
                "YY:YY:YY:YY:YY:YY",
                "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ",
            ],
            "src_endpoint.subnet": [
                "192.168.1.0/24",
                "192.168.1.0/24",
                "10.0.0.0/8",
                "192.168.1.0/24",
                np.nan,
                np.nan,
                "192.168.1.0/24",
            ],
            "dst_endpoint.ip": [
                "192.168.1.10",
                "10.0.0.10",
                "10.0.0.2",
                "192.168.1.11",
                "192.168.1.12",
                "192.168.1.13",
                "192.168.1.10",
            ],
            "dst_endpoint.mac": [
                "DD:DD:DD:DD:DD:DD",
                "EE:EE:EE:EE:EE:EE",
                "FF:FF:FF:FF:FF:FF",
                "GG:GG:GG:GG:GG:GG",
                "WW:WW:WW:WW:WW:WW",
                "VV:VV:VV:VV:VV:VV",
                "DD:DD:DD:DD:DD:DD",
            ],
            "dst_endpoint.subnet": [
                "192.168.1.0/24",
                "10.0.0.0/8",
                "10.0.0.0/8",
                "192.168.1.0/24",
                "192.168.1.0/24",
                "192.168.1.0/24",
                "192.168.1.0/24",
            ],
            "service.name": ["HTTP", "DNS", "SSH", "HTTPS", "FTP", "SMB", "HTTP"],
            "dst_endpoint.port": [80, 53, 22, 443, 21, 445, 80],
            # Add other required columns, even if empty for this test
            "connection_info.protocol_ver_id": [4] * 7,
            "connection_info.direction_name": ["inbound"] * 7,
            "service.port_type": [PortType.KNOWN.name] * 7,
            "service.description": [""] * 7,
            "service.information_categories": [""] * 7,
            "service.risk_categories": [""] * 7,
            "service.risk_basis": [""] * 7,
            "service.environment_exposure": [""] * 7,
            "service.protocol_posture": [""] * 7,
            "service.is_ot": [False] * 7,
        }
        traffic_df = pd.DataFrame(traffic_data)

        # Mock the manufacturers_df that Analyzer expects
        mock_manufacturers_df = pd.DataFrame(
            {"manufacturer": ["Test Mfg"]}, index=pd.Index(["AA:AA:AA"], name="oui")
        )

        # Create an Analyzer instance, which will call endpoints_df_processing
        analyzer = Analyzer(
            traffic_df, pd.DataFrame(), pd.DataFrame(), mock_file_path_info
        )
        analyzer.manufacturers_df = mock_manufacturers_df  # Manually set the mocked df
        analyzer.traffic_df = traffic_df  # Ensure traffic_df is set for processing
        analyzer.endpoints_df_processing()  # Explicitly call the method under test

        # Assertions
        # Expected MACs: AA, BB, CC, DD, EE, FF, GG, ZZ (8 unique MACs with valid IPs)
        # XX and YY are associated with 0.0.0.0 or ::, so they should be filtered out.
        assert len(analyzer.endpoints_df) == 8
        assert "XX:XX:XX:XX:XX:XX" not in analyzer.endpoints_df.index
        assert "YY:YY:YY:YY:YY:YY" not in analyzer.endpoints_df.index

        # Check a specific device entry (e.g., AA:AA:AA:AA:AA:AA)
        device_aa = analyzer.endpoints_df.loc["AA:AA:AA:AA:AA:AA"]
        assert sorted(device_aa["device.ipv4_ips"]) == sorted(["192.168.1.1"])
        assert sorted(device_aa["device.ipv4_subnets"]) == sorted(["192.168.1.0/24"])
        assert sorted(device_aa["device.sent_services"]) == sorted(["HTTP", "HTTPS"])
        assert sorted(device_aa["device.sent_ports"]) == sorted([80, 443])
        assert "device.ipv6_ips" in device_aa and pd.isna(device_aa["device.ipv6_ips"])
        assert "device.ipv6_subnets" in device_aa and pd.isna(
            device_aa["device.ipv6_subnets"]
        )

        # Check another device entry (e.g., DD:DD:DD:DD:DD:DD)
        device_dd = analyzer.endpoints_df.loc["DD:DD:DD:DD:DD:DD"]
        assert sorted(device_dd["device.ipv4_ips"]) == sorted(["192.168.1.10"])
        assert sorted(device_dd["device.incoming_services"]) == sorted(["HTTP"])
        assert sorted(device_dd["device.incoming_ports"]) == sorted([80])

        # Check ZZ:ZZ:ZZ:ZZ:ZZ:ZZ
        device_zz = analyzer.endpoints_df.loc["ZZ:ZZ:ZZ:ZZ:ZZ:ZZ"]
        assert sorted(device_zz["device.ipv4_ips"]) == sorted(["192.168.1.3"])
        assert sorted(device_zz["device.sent_services"]) == sorted(["HTTP"])
        assert sorted(device_zz["device.sent_ports"]) == sorted([80])

        mock_set_manufacturers.assert_called()
        mock_is_using_ot_services.assert_called()
        mock_is_communicating_with_ot_hosts.assert_called()
        mock_is_public_ip.assert_called()

    @patch("src.app.utils.analysis.Analyzer.get_assessor_data")
    @patch("src.app.utils.analysis.Analyzer.traffic_df_processing")
    @patch("src.app.utils.analysis.Analyzer.endpoints_df_processing")
    @patch("src.app.utils.analysis.Analyzer.services_df_processing")
    def test_ot_cross_segment_communication_count(
        self,
        mock_services_df_processing,
        mock_endpoints_df_processing,
        mock_traffic_df_processing,
        mock_get_assessor_data,
        mock_file_path_info,
    ):
        # Setup traffic_df with cross-segment communication
        traffic_data = {
            "connection_info.type_name": [
                "unicast",
                "unicast",
                "unicast",
                "unicast",
                "unicast",
            ],
            "src_endpoint.ip": [
                "192.168.1.1",
                "192.168.1.2",
                "10.0.0.1",
                "192.168.2.1",
                "192.168.1.1",
            ],
            "src_endpoint.mac": [
                "AA:AA:AA:AA:AA:AA",
                "BB:BB:BB:BB:BB:BB",
                "CC:CC:CC:CC:CC:CC",
                "DD:DD:DD:DD:DD:DD",
                "AA:AA:AA:AA:AA:AA",
            ],
            "src_endpoint.subnet": [
                "192.168.1.0/24",
                "192.168.1.0/24",
                "10.0.0.0/8",
                "192.168.2.0/24",
                "192.168.1.0/24",
            ],
            "dst_endpoint.ip": [
                "192.168.1.10",
                "10.0.0.10",
                "10.0.0.2",
                "192.168.1.10",
                "192.168.2.10",
            ],
            "dst_endpoint.mac": [
                "EE:EE:EE:EE:EE:EE",
                "FF:FF:FF:FF:FF:FF",
                "GG:GG:GG:GG:GG:GG",
                "HH:HH:HH:HH:HH:HH",
                "II:II:II:II:II:II",
            ],
            "dst_endpoint.subnet": [
                "192.168.1.0/24",
                "10.0.0.0/8",
                "10.0.0.0/8",
                "192.168.1.0/24",
                "192.168.2.0/24",
            ],
            "service.name": ["HTTP", "DNS", "SSH", "HTTP", "HTTPS"],
            "dst_endpoint.port": [80, 53, 22, 80, 443],
            "connection_info.protocol_ver_id": [4] * 5,
            "connection_info.direction_name": ["inbound"] * 5,
            "connection_info.type_name": ["unicast"] * 5,
            "service.port_type": [PortType.KNOWN.name] * 5,
            "service.description": [""] * 5,
            "service.information_categories": [""] * 5,
            "service.risk_categories": [""] * 5,
            "service.risk_basis": [""] * 5,
            "service.environment_exposure": [""] * 5,
            "service.protocol_posture": [""] * 5,
            "service.is_ot": [False] * 5,
        }
        traffic_df = pd.DataFrame(traffic_data)

        # Setup endpoints_df with some OT devices
        endpoints_data = {
            "device.mac": [
                "AA:AA:AA:AA:AA:AA",
                "BB:BB:BB:BB:BB:BB",
                "CC:CC:CC:CC:CC:CC",
                "DD:DD:DD:DD:DD:DD",
                "EE:EE:EE:EE:EE:EE",
                "FF:FF:FF:FF:FF:FF",
                "GG:GG:GG:GG:GG:GG",
                "HH:HH:HH:HH:HH:HH",
                "II:II:II:II:II:II",
            ],
            "device.is_ot": [
                True,
                False,
                True,
                False,
                False,
                False,
                False,
                False,
                False,
            ],  # AA and CC are OT
            "device.ipv4_ips": [
                ["192.168.1.1"],
                ["192.168.1.2"],
                ["10.0.0.1"],
                ["192.168.2.1"],
                ["192.168.1.10"],
                ["10.0.0.10"],
                ["10.0.0.2"],
                ["192.168.1.10"],
                ["192.168.2.10"],
            ],
            "device.ipv6_ips": [np.nan] * 9,
            "device.ipv4_subnets": [
                ["192.168.1.0/24"],
                ["192.168.1.0/24"],
                ["10.0.0.0/8"],
                ["192.168.2.0/24"],
                ["192.168.1.0/24"],
                ["10.0.0.0/8"],
                ["10.0.0.0/8"],
                ["192.168.1.0/24"],
                ["192.168.2.0/24"],
            ],
            "device.ipv6_subnets": [np.nan] * 9,
            "device.is_edge": [False] * 9,
            "device.manufacturer": [""] * 9,
            "device.ip_scope": [""] * 9,
            "device.protocol_ver_id": [4] * 9,
            "device.sent_services": [set()] * 9,
            "device.incoming_services": [set()] * 9,
            "device.sent_ports": [set()] * 9,
            "device.incoming_ports": [set()] * 9,
        }
        endpoints_df = pd.DataFrame(endpoints_data).set_index("device.mac")

        analyzer = Analyzer(
            traffic_df, endpoints_df, pd.DataFrame(), mock_file_path_info
        )
        # Manually set the dataframes after init, as init would re-process them
        analyzer.traffic_df = traffic_df
        analyzer.endpoints_df = endpoints_df

        # Expected cross-segment traffic:
        # 1. src=BB:BB:BB:BB:BB:BB (192.168.1.2/192.168.1.0/24) -> dst=FF:FF:FF:FF:FF:FF (10.0.0.10/10.0.0.0/8) - No OT involved
        # 2. src=DD:DD:DD:DD:DD:DD (192.168.2.1/192.168.2.0/24) -> dst=HH:HH:HH:HH:HH:HH (192.168.1.10/192.168.1.0/24) - No OT involved
        # 3. src=AA:AA:AA:AA:AA:AA (192.168.1.1/192.168.1.0/24) -> dst=II:II:II:II:II:II (192.168.2.10/192.168.2.0/24) - AA is OT, this is cross-segment
        # So, 1 OT cross-segment communication.

        count = analyzer.ot_cross_segment_communication_count()
        assert count == 1

        # Test with no cross-segment traffic
        traffic_data_no_cross = {
            "connection_info.type_name": ["unicast"],
            "src_endpoint.ip": ["192.168.1.1"],
            "src_endpoint.mac": ["AA:AA:AA:AA:AA:AA"],
            "src_endpoint.subnet": ["192.168.1.0/24"],
            "dst_endpoint.ip": ["192.168.1.10"],
            "dst_endpoint.mac": ["EE:EE:EE:EE:EE:EE"],
            "dst_endpoint.subnet": ["192.168.1.0/24"],
            "service.name": ["HTTP"],
            "dst_endpoint.port": [80],
            "connection_info.protocol_ver_id": [4],
            "connection_info.direction_name": ["inbound"],
            "service.port_type": [PortType.KNOWN.name],
            "service.description": [""],
            "service.information_categories": [""],
            "service.risk_categories": [""],
            "service.risk_basis": [""] * 1,
            "service.environment_exposure": [""] * 1,
            "service.protocol_posture": [""] * 1,
            "service.is_ot": [False] * 1,
        }
        traffic_df_no_cross = pd.DataFrame(traffic_data_no_cross)
        analyzer_no_cross = Analyzer(
            traffic_df_no_cross, endpoints_df, pd.DataFrame(), mock_file_path_info
        )
        analyzer_no_cross.traffic_df = traffic_df_no_cross
        analyzer_no_cross.endpoints_df = endpoints_df  # Manually set
        count_no_cross = analyzer_no_cross.ot_cross_segment_communication_count()
        assert count_no_cross == 0

        # Test with no OT devices
        endpoints_data_no_ot = {
            "device.mac": ["AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB"],
            "device.is_ot": [False, False],
            "device.ipv4_ips": [["192.168.1.1"], ["192.168.1.2"]],
            "device.ipv6_ips": [np.nan] * 2,
            "device.ipv4_subnets": [["192.168.1.0/24"], ["192.168.1.0/24"]],
            "device.ipv6_subnets": [np.nan] * 2,
            "device.is_edge": [False] * 2,
            "device.manufacturer": [""] * 2,
            "device.ip_scope": [""] * 2,
            "device.protocol_ver_id": [4] * 2,
            "device.sent_services": [set()] * 2,
            "device.incoming_services": [set()] * 2,
            "device.sent_ports": [set()] * 2,
            "device.incoming_ports": [set()] * 2,
        }
        endpoints_df_no_ot = pd.DataFrame(endpoints_data_no_ot).set_index("device.mac")
        analyzer_no_ot = Analyzer(
            traffic_df, endpoints_df_no_ot, pd.DataFrame(), mock_file_path_info
        )
        analyzer_no_ot.traffic_df = traffic_df
        analyzer_no_ot.endpoints_df = endpoints_df_no_ot  # Manually set
        count_no_ot = analyzer_no_ot.ot_cross_segment_communication_count()
        assert count_no_ot == 0


class TestConnectionSuccess:
    @patch("src.app.utils.analysis.Analyzer.get_assessor_data")
    @patch("src.app.utils.analysis.Analyzer.traffic_df_processing")
    @patch("src.app.utils.analysis.Analyzer.endpoints_df_processing")
    @patch("src.app.utils.analysis.Analyzer.services_df_processing")
    def test_connection_success_summary_sf_only(self, *_mocks, mock_file_path_info):
        traffic_df = pd.DataFrame(
            {
                "src_endpoint.ip": ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"],
                "dst_endpoint.ip": ["5.5.5.5", "6.6.6.6", "7.7.7.7", "8.8.8.8"],
                "dst_endpoint.port": [80, 53, 22, 443],
                "connection_info.activity_name": ["SF", "S0", "REJ", "SF"],
            }
        )

        analyzer = Analyzer(
            traffic_df, pd.DataFrame(), pd.DataFrame(), mock_file_path_info
        )
        analyzer.traffic_df = traffic_df

        summary = analyzer.connection_success_summary()
        assert summary["successful_count"] == 2
        assert summary["unsuccessful_count"] == 2
        assert summary["by_state"]["SF"] == 2

    @patch("src.app.utils.analysis.Analyzer.get_assessor_data")
    @patch("src.app.utils.analysis.Analyzer.traffic_df_processing")
    @patch("src.app.utils.analysis.Analyzer.endpoints_df_processing")
    @patch("src.app.utils.analysis.Analyzer.services_df_processing")
    def test_connection_success_lines_success_flag(self, *_mocks, mock_file_path_info):
        traffic_df = pd.DataFrame(
            {
                "src_endpoint.ip": ["1.1.1.1", "2.2.2.2"],
                "dst_endpoint.ip": ["5.5.5.5", "6.6.6.6"],
                "dst_endpoint.port": [80, 53],
                "connection_info.activity_name": ["SF", "S0"],
            }
        )

        analyzer = Analyzer(
            traffic_df, pd.DataFrame(), pd.DataFrame(), mock_file_path_info
        )
        analyzer.traffic_df = traffic_df

        lines = analyzer.connection_success_lines(limit=10)
        assert len(lines) == 2

        # Find the line for dst port 80 (SF)
        sf_line = next(l for l in lines if l["dst_endpoint.port"] == 80)
        assert sf_line["success"] is True
        assert sf_line["state"] == "SF"

        # Find the line for dst port 53 (S0)
        s0_line = next(l for l in lines if l["dst_endpoint.port"] == 53)
        assert s0_line["success"] is False
        assert s0_line["state"] == "S0"
