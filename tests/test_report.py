# Standard Python Libraries
from unittest.mock import MagicMock, PropertyMock, patch

# Third-Party Libraries
import numpy as np
import pandas as pd
import pytest

# cisagov Libraries
from app.utils.analysis import Analyzer
from app.utils.report import (
    DevicePanelModule,
    DevicesModule,
    OTcrossSegmentDetection,
    OTcrossSegmentLinesModule,
    OTServicesModule,
    Report,
    ReportModule,
    ServiceCountModule,
    ServicePanelModule,
    ServiceRiskBreakdownModule,
    SuspiciousOutboundConnectionsDetection,
    SuspiciousOutboundConnectionsModule,
)
from app.utils.utils import FilePathInfo, PortType

# --- Fixtures for Analyzer and DataFrames ---


@pytest.fixture
def mock_analyzer():
    analyzer = MagicMock()
    analyzer.traffic_df = pd.DataFrame(
        {
            "connection_info.type_name": ["unicast", "unicast", "unicast"],
            "src_endpoint.ip": ["192.168.1.1", "192.168.1.2", "10.0.0.1"],
            "src_endpoint.mac": [
                "AA:AA:AA:AA:AA:AA",
                "BB:BB:BB:BB:BB:BB",
                "CC:CC:CC:CC:CC:CC",
            ],
            "src_endpoint.subnet": ["192.168.1.0/24", "192.168.1.0/24", "10.0.0.0/8"],
            "dst_endpoint.ip": ["192.168.1.10", "10.0.0.10", "10.0.0.2"],
            "dst_endpoint.mac": [
                "DD:DD:DD:DD:DD:DD",
                "EE:EE:EE:EE:EE:EE",
                "FF:FF:FF:FF:FF:FF",
            ],
            "dst_endpoint.port": [80, 53, 22],
            "dst_endpoint.subnet": ["192.168.1.0/24", "10.0.0.0/8", "10.0.0.0/8"],
            "service.name": ["HTTP", "DNS", "SSH"],
            "service.port_type": [
                PortType.KNOWN.name,
                PortType.KNOWN.name,
                PortType.KNOWN.name,
            ],
            "service.information_categories": ["Web", "DNS", "Industrial Protocol"],
            "service.risk_categories": ["Low", "Low", "High"],
            "service.risk_basis": ["Observed", "Observed", "Credible"],
            "service.environment_exposure": ["Internal", "Internal", "External"],
            "service.protocol_posture": [
                "Conditionally Risky",
                "Conditionally Risky",
                "Inherently Risky",
            ],
            "service.is_ot": [False, False, True],
        }
    )
    analyzer.endpoints_df = pd.DataFrame(
        {
            "device.mac": [
                "AA:AA:AA:AA:AA:AA",
                "BB:BB:BB:BB:BB:BB",
                "CC:CC:CC:CC:CC:CC",
                "DD:DD:DD:DD:DD:DD",
                "EE:EE:EE:EE:EE:EE",
                "FF:FF:FF:FF:FF:FF",
            ],
            "device.is_ot": [True, False, True, False, False, False],
            "device.is_edge": [False, False, False, False, True, False],
            "device.manufacturer": ["MfgA", "MfgB", "MfgC", "MfgD", "MfgE", "MfgF"],
            "device.ipv4_ips": [
                ["192.168.1.1"],
                ["192.168.1.2"],
                ["10.0.0.1"],
                ["192.168.1.10"],
                ["10.0.0.10"],
                ["10.0.0.2"],
            ],
            "device.ipv6_ips": [np.nan] * 6,
            "device.ipv4_subnets": [
                ["192.168.1.0/24"],
                ["192.168.1.0/24"],
                ["10.0.0.0/8"],
                ["192.168.1.0/24"],
                ["10.0.0.0/8"],
                ["10.0.0.0/8"],
            ],
            "device.ipv6_subnets": [np.nan] * 6,
            "device.incoming_services": [
                set(),
                set(),
                set(),
                {"HTTP"},
                {"DNS"},
                {"SSH"},
            ],
            "device.sent_services": [{"HTTP"}, {"DNS"}, {"SSH"}, set(), set(), set()],
        }
    ).set_index("device.mac")
    analyzer.services_df = pd.DataFrame(
        {
            "service.name": ["HTTP", "DNS", "SSH"],
            "service.port_type": [
                PortType.KNOWN.name,
                PortType.KNOWN.name,
                PortType.KNOWN.name,
            ],
            "service.description": [
                "Web traffic",
                "Domain Name System",
                "Secure Shell",
            ],
            "service.information_categories": ["Web", "DNS", "Industrial Protocol"],
            "service.risk_categories": ["Low", "Low", "High"],
            "service.risk_basis": ["Observed", "Observed", "Credible"],
            "service.environment_exposure": ["Internal", "Internal", "External"],
            "service.protocol_posture": [
                "Conditionally Risky",
                "Conditionally Risky",
                "Inherently Risky",
            ],
            "service.is_ot": [False, False, True],
        }
    )
    analyzer.ot_cross_segment_communication_count.return_value = 1
    analyzer.service_counts_in_traffic.return_value = {
        "known_services": [{"name": "HTTP", "port": 80, "count": 1}],
        "unknown_services": {},
    }
    analyzer.service_category_map.return_value = {"High": ["SSH"]}
    return analyzer


@pytest.fixture
def mock_file_path_info():
    return FilePathInfo(
        path_to_pcap="/tmp/test.pcap",
        path_to_zeek="/tmp/zeek_output",
        path_to_zeek_scripts="/tmp/zeek_scripts",
        path_to_assessor_data="/tmp/assessor_data",
    )


# --- Test Report Class ---


@patch("app.utils.report.ServicePanelModule")
@patch("app.utils.report.DevicePanelModule")
@patch("app.utils.report.ServiceRiskBreakdownModule")
@patch("app.utils.report.ServiceCountModule")
@patch("app.utils.report.RiskBasisBreakdownModule")
@patch("app.utils.report.ExposureBreakdownModule")
@patch("app.utils.report.ProtocolPostureModule")
@patch("app.utils.report.ConnectionSuccessModule")
@patch("app.utils.report.SuspiciousOutboundConnectionsModule")
@patch("app.utils.report.OTcrossSegmentLinesModule")
@patch("app.utils.report.DevicesModule")
@patch("app.utils.report.OTServicesModule")
@patch("app.utils.report.OTcrossSegmentDetection")
@patch("app.utils.report.SuspiciousOutboundConnectionsDetection")
def test_report_init(
    MockSuspiciousOutboundConnectionsDetection,
    MockOTcrossSegmentDetection,
    MockOTServicesModule,
    MockDevicesModule,
    MockOTcrossSegmentLinesModule,
    MockSuspiciousOutboundConnectionsModule,
    MockProtocolPostureModule,
    MockConnectionSuccessModule,
    MockExposureBreakdownModule,
    MockRiskBasisBreakdownModule,
    MockServiceCountModule,
    MockServiceRiskBreakdownModule,
    MockDevicePanelModule,
    MockServicePanelModule,
    mock_analyzer,
):
    # Configure mocks for modules
    mock_modules = {
        "service_panel": MockServicePanelModule.return_value,
        "device_panel": MockDevicePanelModule.return_value,
        "service_risk_breakdown_panel": MockServiceRiskBreakdownModule.return_value,
        "service_count_panel": MockServiceCountModule.return_value,
        "risk_basis_breakdown_panel": MockRiskBasisBreakdownModule.return_value,
        "exposure_breakdown_panel": MockExposureBreakdownModule.return_value,
        "protocol_posture_panel": MockProtocolPostureModule.return_value,
        "connection_success_panel": MockConnectionSuccessModule.return_value,
        "suspicious_outbound_connections_panel": MockSuspiciousOutboundConnectionsModule.return_value,
        "ot_cross_segment_lines_panel": MockOTcrossSegmentLinesModule.return_value,
        "ot_devices": MockDevicesModule.return_value,
        "it_devices": MockDevicesModule.return_value,
        "edge_devices": MockDevicesModule.return_value,
        "ot_services": MockOTServicesModule.return_value,
    }
    for name, mock_instance in mock_modules.items():
        type(mock_instance).name = PropertyMock(return_value=name)
        mock_instance.data = {f"{name}_data": True}  # Simulate data generation

    # Configure mocks for detections
    mock_ot_cross_segment_detection_instance = MockOTcrossSegmentDetection.return_value
    mock_ot_cross_segment_detection_instance.run_detection.return_value = True
    type(mock_ot_cross_segment_detection_instance).name = PropertyMock(
        return_value="ot_cross_segment_alert"
    )
    type(mock_ot_cross_segment_detection_instance).executive_summary = PropertyMock(
        return_value="OT Cross-Segment Summary"
    )

    mock_suspicious_outbound_detection_instance = (
        MockSuspiciousOutboundConnectionsDetection.return_value
    )
    mock_suspicious_outbound_detection_instance.run_detection.return_value = (
        False  # Simulate no detection
    )
    type(mock_suspicious_outbound_detection_instance).name = PropertyMock(
        return_value="suspicious_outbound_connections_detection"
    )
    type(mock_suspicious_outbound_detection_instance).executive_summary = PropertyMock(
        return_value=""
    )

    report = Report(mock_analyzer)

    # Assert that all modules were instantiated
    MockServicePanelModule.assert_called_once_with(mock_analyzer)
    MockDevicePanelModule.assert_called_once_with(mock_analyzer)
    MockConnectionSuccessModule.assert_called_once_with(mock_analyzer)
    # ... assert other modules ...
    MockOTServicesModule.assert_called_once_with(mock_analyzer)

    # Assert DevicesModule was called three times with correct filters
    assert MockDevicesModule.call_count == 3
    # Check specific calls (order might vary, so check args)
    devices_calls = MockDevicesModule.call_args_list
    assert any(call.kwargs["name"] == "ot_devices" for call in devices_calls)
    assert any(call.kwargs["name"] == "it_devices" for call in devices_calls)
    assert any(call.kwargs["name"] == "edge_devices" for call in devices_calls)

    # Assert detections were instantiated
    MockOTcrossSegmentDetection.assert_called_once()
    MockSuspiciousOutboundConnectionsDetection.assert_called_once()

    # Assert executive summary is built correctly
    assert report.data["executive_summary"] == {
        "ot_cross_segment_alert": "OT Cross-Segment Summary"
    }
    # Assert module data is included
    assert report.data["modules"]["service_panel"] == {"service_panel_data": True}
    assert report.data["modules"]["device_panel"] == {"device_panel_data": True}
    assert report.data["modules"]["connection_success_panel"] == {
        "connection_success_panel_data": True
    }
    # ... assert other module data ...


# --- Test ReportModule ABC ---


def test_report_module_lazy_loading():
    mock_analyzer = MagicMock()

    class ConcreteModule(ReportModule):
        @property
        def name(self):
            return "concrete_module"

        def generate_data(self):
            return {"key": "value"}

    module = ConcreteModule(mock_analyzer)
    assert module._data is None  # Should be None initially

    data = module.data  # Access data property
    assert data == {"key": "value"}
    assert module._data == {"key": "value"}  # Should be cached

    # Call again, generate_data should not be called again
    with patch.object(module, "generate_data") as mock_generate_data:
        module.data
        mock_generate_data.assert_not_called()


# --- Test Concrete ReportModule Subclasses ---


class TestDevicePanelModule:
    def test_generate_data(self, mock_analyzer):
        # Ensure ot_cross_segment_communication_count is called
        mock_analyzer.ot_cross_segment_communication_count.return_value = 5

        # Setup endpoints_df for specific counts
        mock_analyzer.endpoints_df = pd.DataFrame(
            {
                "device.is_ot": [True, False, True, False, False],
                "device.is_edge": [False, True, False, False, False],
            }
        )

        module = DevicePanelModule(mock_analyzer)
        data = module.generate_data()

        assert data["hosts"] == 5
        assert data["ot_hosts"] == 2
        assert data["it_hosts"] == 1  # One non-OT, non-Edge
        assert data["edge_hosts"] == 1
        assert data["ot_cross_segment"] == 5
        mock_analyzer.ot_cross_segment_communication_count.assert_called_once()


class TestServicePanelModule:
    def test_generate_data(self, mock_analyzer):
        # Setup traffic_df for service counts
        mock_analyzer.traffic_df = pd.DataFrame(
            {
                "service.name": ["HTTP", "DNS", "HTTP", "UNKNOWN_1", "SSH"],
                "service.port_type": [
                    PortType.KNOWN.name,
                    PortType.KNOWN.name,
                    PortType.KNOWN.name,
                    PortType.UNKNOWN.name,
                    PortType.KNOWN.name,
                ],
            }
        )
        # Setup services_df for risk and OT service counts
        mock_analyzer.services_df = pd.DataFrame(
            {
                "service.name": ["HTTP", "DNS", "SSH", "UNKNOWN_1"],
                "service.information_categories": [
                    "Web",
                    "DNS",
                    "Industrial Protocol",
                    np.nan,
                ],
                "service.risk_categories": ["Low", np.nan, "High", np.nan],
            }
        )

        module = ServicePanelModule(mock_analyzer)
        data = module.generate_data()

        assert data["num_known_services"] == 3  # HTTP, DNS, SSH
        assert data["num_ot_services"] == 1  # SSH (Industrial Protocol)
        assert data["num_risky_services"] == 2  # HTTP (Low), SSH (High)
        assert data["num_unknown_services"] == 1  # UNKNOWN_1


class TestServiceRiskBreakdownModule:
    def test_generate_data(self, mock_analyzer):
        # Mock the utility function and analyzer method
        with patch(
            "app.utils.report.count_values_in_list_column",
            return_value={"High": 1, "Low": 2},
        ):
            mock_analyzer.service_category_map.return_value = {
                "High": ["SSH"],
                "Low": ["HTTP", "DNS"],
            }

            module = ServiceRiskBreakdownModule(mock_analyzer)
            data = module.generate_data()

            assert data["risk_category_counts"] == {"High": 1, "Low": 2}
            assert data["risk_category_services"] == {
                "High": ["SSH"],
                "Low": ["HTTP", "DNS"],
            }
            mock_analyzer.service_category_map.assert_called_once_with(
                "service.risk_categories"
            )


class TestServiceCountModule:
    def test_generate_data(self, mock_analyzer):
        mock_analyzer.traffic_df = pd.DataFrame(
            {
                "service.name": ["HTTP", "DNS", "UNKNOWN_1"],
                "service.port_type": [
                    PortType.KNOWN.name,
                    PortType.KNOWN.name,
                    PortType.UNKNOWN.name,
                ],
                "dst_endpoint.port": [80, 53, 12345],
            }
        )
        mock_analyzer.service_counts_in_traffic.return_value = {
            "known_services": [
                {"name": "HTTP", "port": 80, "count": 1},
                {"name": "DNS", "port": 53, "count": 1},
            ],
            "unknown_services": {"UNKNOWN_1": 1},
        }

        module = ServiceCountModule(mock_analyzer)
        data = module.generate_data()

        assert data["service_count"] == 3
        assert data["service_connections_count"] == {
            "known_services": [
                {"name": "HTTP", "port": 80, "count": 1},
                {"name": "DNS", "port": 53, "count": 1},
            ],
            "unknown_services": {"UNKNOWN_1": 1},
        }
        mock_analyzer.service_counts_in_traffic.assert_called_once()


class TestSuspiciousOutboundConnectionsModule:
    def test_generate_data(self, mock_analyzer):
        # Setup traffic_df for outbound traffic from OT devices
        mock_analyzer.traffic_df = pd.DataFrame(
            {
                "connection_info.direction_name": [
                    "outbound",
                    "inbound",
                    "outbound",
                    "outbound",
                ],
                "src_endpoint.ip": [
                    "192.168.1.1",
                    "192.168.1.10",
                    "10.0.0.1",
                    "192.168.1.2",
                ],
                "dst_endpoint.ip": [
                    "8.8.8.8",
                    "192.168.1.1",
                    "1.1.1.1",
                    "192.168.1.11",
                ],
                "dst_endpoint.port": [53, 80, 443, 8080],
                "service.name": ["DNS", "HTTP", "HTTPS", "UNKNOWN"],
                "dst_endpoint.mac": ["OT_MAC_1", "IT_MAC_1", "OT_MAC_2", "IT_MAC_2"],
            }
        )
        # Setup endpoints_df to mark some MACs as OT
        mock_analyzer.endpoints_df = pd.DataFrame(
            {
                "device.is_ot": [True, False, True, False],
            },
            index=["OT_MAC_1", "IT_MAC_1", "OT_MAC_2", "IT_MAC_2"],
        )

        module = SuspiciousOutboundConnectionsModule(mock_analyzer)
        data = module.generate_data()

        expected_data = [
            {
                "src_endpoint.ip": "192.168.1.1",
                "dst_endpoint.ip": "8.8.8.8",
                "dst_endpoint.port": 53,
                "service.name": "DNS",
                "count": 1,
            },
            {
                "src_endpoint.ip": "10.0.0.1",
                "dst_endpoint.ip": "1.1.1.1",
                "dst_endpoint.port": 443,
                "service.name": "HTTPS",
                "count": 1,
            },
        ]
        assert data == expected_data


class TestOTcrossSegmentLinesModule:
    @patch("app.utils.report.ipaddress.ip_address")
    def test_is_excluded_cross_segment_ip(self, mock_ip_address):
        # Test cases for _is_excluded_cross_segment_ip
        mock_ip_address.return_value.is_link_local = False
        mock_ip_address.return_value.is_multicast = False
        mock_ip_address.return_value.__eq__.return_value = False  # For 255.255.255.255

        # Valid IP
        assert not OTcrossSegmentLinesModule._is_excluded_cross_segment_ip(
            "192.168.1.1"
        )

        # Link-local
        mock_ip_address.return_value.is_link_local = True
        assert OTcrossSegmentLinesModule._is_excluded_cross_segment_ip("169.254.0.1")
        mock_ip_address.return_value.is_link_local = False

        # Multicast
        mock_ip_address.return_value.is_multicast = True
        assert OTcrossSegmentLinesModule._is_excluded_cross_segment_ip("224.0.0.1")
        mock_ip_address.return_value.is_multicast = False

        # Broadcast
        mock_ip_address.return_value.__eq__.return_value = True
        assert OTcrossSegmentLinesModule._is_excluded_cross_segment_ip(
            "255.255.255.255"
        )
        mock_ip_address.return_value.__eq__.return_value = False

        # Invalid IP
        mock_ip_address.side_effect = ValueError
        assert not OTcrossSegmentLinesModule._is_excluded_cross_segment_ip("invalid-ip")
        mock_ip_address.side_effect = None  # Reset side effect

        # Non-string
        assert not OTcrossSegmentLinesModule._is_excluded_cross_segment_ip(123)

    def test_preferred_ip_for_mac(self, mock_analyzer):
        # Test with IPv4
        assert (
            OTcrossSegmentLinesModule._preferred_ip_for_mac(
                mock_analyzer.endpoints_df, "AA:AA:AA:AA:AA:AA"
            )
            == "192.168.1.1"
        )

        new_row = pd.Series(
            {
                "device.is_ot": False,
                "device.is_edge": False,
                "device.manufacturer": "MfgZ",
                "device.ipv4_ips": np.nan,
                "device.ipv6_ips": ["fe80::1"],
                "device.ipv4_subnets": np.nan,
                "device.ipv6_subnets": np.nan,
                "device.incoming_services": set(),
                "device.sent_services": set(),
            },
            dtype=object,
        )
        # Test with IPv6 (if present)
        mock_analyzer.endpoints_df.loc["ZZ:ZZ:ZZ:ZZ:ZZ:ZZ"] = new_row
        assert (
            OTcrossSegmentLinesModule._preferred_ip_for_mac(
                mock_analyzer.endpoints_df, "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ"
            )
            == "fe80::1"
        )
        # Test with no IPs
        mock_analyzer.endpoints_df.loc["YY:YY:YY:YY:YY:YY", :] = {
            "device.is_ot": False,
            "device.is_edge": False,
            "device.manufacturer": "MfgY",
            "device.ipv4_ips": np.nan,
            "device.ipv6_ips": np.nan,
            "device.ipv4_subnets": np.nan,
            "device.ipv6_subnets": np.nan,
            "device.incoming_services": set(),
            "device.sent_services": set(),
        }
        assert (
            OTcrossSegmentLinesModule._preferred_ip_for_mac(
                mock_analyzer.endpoints_df, "YY:YY:YY:YY:YY:YY"
            )
            is None
        )
        # Test with non-existent MAC
        assert (
            OTcrossSegmentLinesModule._preferred_ip_for_mac(
                mock_analyzer.endpoints_df, "NON_EXISTENT"
            )
            is None
        )

    def test_generate_data_no_cross_segment_traffic(self, mock_analyzer):
        # Traffic where src and dst subnets are the same
        mock_analyzer.traffic_df = pd.DataFrame(
            {
                "connection_info.type_name": ["unicast"],
                "src_endpoint.ip": ["192.168.1.1"],
                "src_endpoint.mac": ["AA:AA:AA:AA:AA:AA"],
                "src_endpoint.subnet": ["192.168.1.0/24"],
                "dst_endpoint.ip": ["192.168.1.10"],
                "dst_endpoint.mac": ["DD:DD:DD:DD:DD:DD"],
                "dst_endpoint.port": [80],
                "dst_endpoint.subnet": ["192.168.1.0/24"],
                "service.name": ["HTTP"],
                "service.port_type": [PortType.KNOWN.name],
                "service.information_categories": ["Web"],
                "service.risk_categories": ["Low"],
                "service.risk_basis": ["Observed"],
                "service.environment_exposure": ["Internal"],
                "service.protocol_posture": ["Conditionally Risky"],
                "service.is_ot": [False],
            }
        )
        module = OTcrossSegmentLinesModule(mock_analyzer)
        data = module.generate_data()
        assert data == {
            "lines": [],
            "subnet_pair_counts": [],
            "dst_subnet_counts": [],
            "ot_device_counts": [],
        }

    def test_generate_data_with_cross_segment_traffic(self, mock_analyzer):
        # Traffic with cross-segment communication involving OT devices
        mock_analyzer.traffic_df = pd.DataFrame(
            {
                "connection_info.type_name": [
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
                ],
                "src_endpoint.mac": [
                    "AA:AA:AA:AA:AA:AA",
                    "BB:BB:BB:BB:BB:BB",
                    "CC:CC:CC:CC:CC:CC",
                    "AA:AA:AA:AA:AA:AA",
                ],
                "src_endpoint.subnet": [
                    "192.168.1.0/24",
                    "192.168.1.0/24",
                    "10.0.0.0/8",
                    "192.168.1.0/24",
                ],
                "dst_endpoint.ip": [
                    "10.0.0.10",
                    "192.168.2.10",
                    "192.168.1.10",
                    "10.0.0.10",
                ],
                "dst_endpoint.mac": [
                    "EE:EE:EE:EE:EE:EE",
                    "FF:FF:FF:FF:FF:FF",
                    "DD:DD:DD:DD:DD:DD",
                    "EE:EE:EE:EE:EE:EE",
                ],
                "dst_endpoint.port": [80, 53, 22, 80],
                "dst_endpoint.subnet": [
                    "10.0.0.0/8",
                    "192.168.2.0/24",
                    "192.168.1.0/24",
                    "10.0.0.0/8",
                ],
                "service.name": ["HTTP", "DNS", "SSH", "HTTP"],
                "service.port_type": [PortType.KNOWN.name] * 4,
                "service.information_categories": [
                    "Web",
                    "DNS",
                    "Industrial Protocol",
                    "Web",
                ],
                "service.risk_categories": ["Low", "Low", "High", "Low"],
                "service.risk_basis": ["Observed", "Observed", "Credible", "Observed"],
                "service.environment_exposure": [
                    "Internal",
                    "Internal",
                    "External",
                    "Internal",
                ],
                "service.protocol_posture": [
                    "Conditionally Risky",
                    "Conditionally Risky",
                    "Inherently Risky",
                    "Conditionally Risky",
                ],
                "service.is_ot": [False, False, True, False],
            }
        )
        # Endpoints: AA and CC are OT
        mock_analyzer.endpoints_df = pd.DataFrame(
            {
                "device.is_ot": [True, False, True, False, False, False],
                "device.is_edge": [False, False, False, False, True, False],
                "device.ipv4_ips": [
                    ["192.168.1.1"],
                    ["192.168.1.2"],
                    ["10.0.0.1"],
                    ["192.168.1.10"],
                    ["10.0.0.10"],
                    ["10.0.0.2"],
                ],
                "device.ipv6_ips": [np.nan] * 6,
                "device.ipv4_subnets": [
                    ["192.168.1.0/24"],
                    ["192.168.1.0/24"],
                    ["10.0.0.0/8"],
                    ["192.168.1.0/24"],
                    ["10.0.0.0/8"],
                    ["10.0.0.0/8"],
                ],
                "device.ipv6_subnets": [np.nan] * 6,
                "device.incoming_services": [
                    set(),
                    set(),
                    set(),
                    {"HTTP"},
                    {"DNS"},
                    {"SSH"},
                ],
                "device.sent_services": [
                    {"HTTP"},
                    {"DNS"},
                    {"SSH"},
                    set(),
                    set(),
                    set(),
                ],
            },
            index=[
                "AA:AA:AA:AA:AA:AA",
                "BB:BB:BB:BB:BB:BB",
                "CC:CC:CC:CC:CC:CC",
                "DD:DD:DD:DD:DD:DD",
                "EE:EE:EE:EE:EE:EE",
                "FF:FF:FF:FF:FF:FF",
            ],
        )

        module = OTcrossSegmentLinesModule(mock_analyzer)
        data = module.generate_data()

        # Expected lines:
        # 1. AA:AA:AA:AA:AA:AA (OT) -> EE:EE:EE:EE:EE:EE (not OT) across subnets (192.168.1.0/24 -> 10.0.0.0/8)
        # 2. CC:CC:CC:CC:CC:CC (OT) -> DD:DD:DD:DD:DD:DD (not OT) across subnets (10.0.0.0/8 -> 192.168.1.0/24)
        # 3. AA:AA:AA:AA:AA:AA (OT) -> EE:EE:EE:EE:EE:EE (not OT) across subnets (192.168.1.0/24 -> 10.0.0.0/8) - duplicate of 1

        assert len(data["lines"]) == 2  # Unique lines
        assert {
            "src_endpoint.ip": "192.168.1.1",
            "dst_endpoint.ip": "10.0.0.10",
            "dst_endpoint.port": 80,
            "service.name": "HTTP",
            "count": 2,
        } in data["lines"]
        assert {
            "src_endpoint.ip": "10.0.0.1",
            "dst_endpoint.ip": "192.168.1.10",
            "dst_endpoint.port": 22,
            "service.name": "SSH",
            "count": 1,
        } in data["lines"]

        assert len(data["subnet_pair_counts"]) == 2
        assert {
            "src_subnet": "192.168.1.0/24",
            "dst_subnet": "10.0.0.0/8",
            "count": 2,
        } in data["subnet_pair_counts"]
        assert {
            "src_subnet": "10.0.0.0/8",
            "dst_subnet": "192.168.1.0/24",
            "count": 1,
        } in data["subnet_pair_counts"]

        assert len(data["dst_subnet_counts"]) == 2
        assert {"dst_subnet": "10.0.0.0/8", "count": 2} in data["dst_subnet_counts"]
        assert {"dst_subnet": "192.168.1.0/24", "count": 1} in data["dst_subnet_counts"]

        assert len(data["ot_device_counts"]) == 2
        assert {"src_device_ip": "192.168.1.1", "count": 2} in data["ot_device_counts"]
        assert {"src_device_ip": "10.0.0.1", "count": 1} in data["ot_device_counts"]


class TestDevicesModule:
    def test_generate_data_ot_devices(self, mock_analyzer):

        def ot_device_filter(df):
            return df["device.is_ot"]

        module = DevicesModule(
            mock_analyzer, name="ot_devices", device_filter=ot_device_filter
        )
        data = module.generate_data()

        assert len(data) == 2  # AA:AA:AA:AA:AA:AA and CC:CC:CC:CC:CC:CC are OT
        assert {
            "manufacturer": "MfgA",
            "ipv4_ips": ["192.168.1.1"],
            "ipv6_ips": None,
            "ipv4_subnets": ["192.168.1.0/24"],
            "ipv6_subnets": None,
            "incoming_services": [],
            "sent_services": ["HTTP"],
        } in data
        assert {
            "manufacturer": "MfgC",
            "ipv4_ips": ["10.0.0.1"],
            "ipv6_ips": None,
            "ipv4_subnets": ["10.0.0.0/8"],
            "ipv6_subnets": None,
            "incoming_services": [],
            "sent_services": ["SSH"],
        } in data

    def test_generate_data_it_devices(self, mock_analyzer):

        def it_device_filter(df):
            return (~df["device.is_ot"]) & (~df["device.is_edge"])

        module = DevicesModule(
            mock_analyzer, name="it_devices", device_filter=it_device_filter
        )
        data = module.generate_data()

        assert len(data) == 3  # BB, DD, FF are IT
        assert {
            "manufacturer": "MfgB",
            "ipv4_ips": ["192.168.1.2"],
            "ipv6_ips": None,
            "ipv4_subnets": ["192.168.1.0/24"],
            "ipv6_subnets": None,
            "incoming_services": [],
            "sent_services": ["DNS"],
        } in data
        assert {
            "manufacturer": "MfgD",
            "ipv4_ips": ["192.168.1.10"],
            "ipv6_ips": None,
            "ipv4_subnets": ["192.168.1.0/24"],
            "ipv6_subnets": None,
            "incoming_services": ["HTTP"],
            "sent_services": [],
        } in data
        assert {
            "manufacturer": "MfgF",
            "ipv4_ips": ["10.0.0.2"],
            "ipv6_ips": None,
            "ipv4_subnets": ["10.0.0.0/8"],
            "ipv6_subnets": None,
            "incoming_services": ["SSH"],
            "sent_services": [],
        } in data

    def test_generate_data_edge_devices(self, mock_analyzer):
        def edge_device_filter(df):
            return df["device.is_edge"]

        module = DevicesModule(
            mock_analyzer, name="edge_devices", device_filter=edge_device_filter
        )
        data = module.generate_data()

        assert len(data) == 1  # EE is Edge
        assert {
            "manufacturer": "MfgE",
            "ipv4_ips": ["10.0.0.10"],
            "ipv6_ips": None,
            "ipv4_subnets": ["10.0.0.0/8"],
            "ipv6_subnets": None,
            "incoming_services": ["DNS"],
            "sent_services": [],
        } in data

    def test_prep_df_for_json_empty_df(self):
        module = DevicesModule(MagicMock(), name="test", device_filter=lambda df: df)
        empty_df = pd.DataFrame(columns=["device.manufacturer", "device.ipv4_ips"])
        columns = {"device.manufacturer": "manufacturer", "device.ipv4_ips": "ipv4_ips"}
        result = module._prep_df_for_json(empty_df, columns)
        assert result == []

    def test_prep_df_for_json_with_data(self):
        module = DevicesModule(MagicMock(), name="test", device_filter=lambda df: df)
        df = pd.DataFrame(
            {
                "device.manufacturer": ["MfgX", "MfgY"],
                "device.ipv4_ips": [["1.1.1.1"], ["2.2.2.2"]],
                "device.some_other_col": ["a", "b"],
            }
        )
        columns = {"device.manufacturer": "manufacturer", "device.ipv4_ips": "ipv4_ips"}
        result = module._prep_df_for_json(df, columns)
        expected = [
            {"manufacturer": "MfgX", "ipv4_ips": ["1.1.1.1"]},
            {"manufacturer": "MfgY", "ipv4_ips": ["2.2.2.2"]},
        ]
        assert result == expected


class TestOTServicesModule:
    def test_services_df_processing_removes_nans(self, mock_file_path_info):
        """
        Verify that services_df_processing converts np.nan to None
        to ensure JSON compatibility.
        """
        with (
            patch("app.utils.analysis.Analyzer.get_assessor_data"),
            patch("app.utils.analysis.Analyzer.traffic_df_processing"),
            patch("app.utils.analysis.Analyzer.endpoints_df_processing"),
            patch("app.utils.analysis.Analyzer.services_df_processing"),
        ):
            analyzer = Analyzer(
                pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), mock_file_path_info
            )

        analyzer.traffic_df = pd.DataFrame(
            {
                "src_endpoint.ip": ["192.168.1.1"],
                "dst_endpoint.ip": ["192.168.1.10"],
                "dst_endpoint.port": [80],
                "service.name": ["HTTP"],
                "service.port_type": [PortType.KNOWN.name],
                "service.description": ["Web"],
                "service.information_categories": ["Web"],
                "service.risk_categories": [np.nan],  # The poison value
                "service.risk_basis": ["Observed"],
                "service.environment_exposure": ["Internal"],
                "service.protocol_posture": ["Conditionally Risky"],
                "service.is_ot": [False],
            }
        )

        # Initialize services_df schema (as the real init would)
        analyzer.services_df = pd.DataFrame(
            columns=[
                "service.name",
                "service.port_type",
                "service.description",
                "service.information_categories",
                "service.risk_categories",
                "service.risk_basis",
                "service.environment_exposure",
                "service.protocol_posture",
                "service.is_ot",
            ]
        )

        analyzer.services_df_processing()

        val = analyzer.services_df.iloc[0]["service.risk_categories"]
        assert val is None
        assert pd.isna(val) is not False  # Ensure it's not NaN

        # Standard Python Libraries
        import json

        try:
            json.dumps(analyzer.services_df.to_dict(orient="records"))
        except ValueError as e:
            pytest.fail(f"services_df still contains non-JSON compliant values: {e}")

    def test_generate_data(self, mock_analyzer):
        # Setup services_df with OT and non-OT services
        mock_analyzer.services_df = pd.DataFrame(
            {
                "service.name": ["HTTP", "Modbus", "DNS", "S7Comm"],
                "service.information_categories": [
                    "Web",
                    "Industrial Protocol",
                    "DNS",
                    "Industrial Protocol",
                ],
                "service.description": [
                    "Web traffic",
                    "Modbus Protocol",
                    "Domain Name System",
                    "Siemens S7 Communication",
                ],
                "service.port_type": [PortType.KNOWN.name] * 4,
                "service.risk_categories": ["Low", "High", "Low", "High"],
                "service.risk_basis": ["Observed", "Credible", "Observed", "Credible"],
                "service.environment_exposure": [
                    "Internal",
                    "External",
                    "Internal",
                    "External",
                ],
                "service.protocol_posture": [
                    "Conditionally Risky",
                    "Inherently Risky",
                    "Conditionally Risky",
                    "Inherently Risky",
                ],
                "service.is_ot": [False, True, False, True],
            }
        )

        module = OTServicesModule(mock_analyzer)
        data = module.generate_data()

        expected_data = [
            {
                "service.name": "Modbus",
                "service.information_categories": "Industrial Protocol",
                "service.description": "Modbus Protocol",
                "service.port_type": "KNOWN",
                "service.risk_categories": "High",
                "service.risk_basis": "Credible",
                "service.environment_exposure": "External",
                "service.protocol_posture": "Inherently Risky",
                "service.is_ot": True,
            },
            {
                "service.name": "S7Comm",
                "service.information_categories": "Industrial Protocol",
                "service.description": "Siemens S7 Communication",
                "service.port_type": "KNOWN",
                "service.risk_categories": "High",
                "service.risk_basis": "Credible",
                "service.environment_exposure": "External",
                "service.protocol_posture": "Inherently Risky",
                "service.is_ot": True,
            },
        ]
        # Convert to DataFrame and then to dict to handle potential order differences
        assert pd.DataFrame(data).to_dict("records") == pd.DataFrame(
            expected_data
        ).to_dict("records")


# --- Test DetectionModule Subclasses ---


class TestOTcrossSegmentDetection:
    def test_run_detection_true(self):
        mock_module = MagicMock()
        mock_module.data = {"lines": [{"src": "1.1.1.1", "dst": "2.2.2.2"}]}
        detection = OTcrossSegmentDetection([mock_module])
        assert detection.run_detection() is True

    def test_run_detection_false(self):
        mock_module = MagicMock()
        mock_module.data = {"lines": []}
        detection = OTcrossSegmentDetection([mock_module])
        assert detection.run_detection() is False

    def test_executive_summary_no_detection(self):
        mock_module = MagicMock()
        mock_module.data = {"lines": []}
        detection = OTcrossSegmentDetection([mock_module])
        assert detection.executive_summary == ""

    def test_executive_summary_with_detection(self):
        mock_module = MagicMock()
        mock_module.data = {
            "lines": [
                {
                    "src_endpoint.ip": "192.168.1.1",
                    "dst_endpoint.ip": "10.0.0.10",
                    "dst_endpoint.port": 80,
                    "service.name": "HTTP",
                    "count": 5,
                },
                {
                    "src_endpoint.ip": "10.0.0.1",
                    "dst_endpoint.ip": "192.168.1.10",
                    "dst_endpoint.port": 22,
                    "service.name": "SSH",
                    "count": 1,
                },
            ]
        }
        detection = OTcrossSegmentDetection([mock_module])
        summary = detection.executive_summary
        assert "**FINDING: OT Cross-Segment Communications Detected**" in summary
        assert (
            "2 cross-segment communication example(s) involving OT assets were identified."
            in summary
        )
        assert "- 192.168.1.1 → 10.0.0.10:80 (HTTP) - 5x" in summary
        assert "- 10.0.0.1 → 192.168.1.10:22 (SSH) - 1x" in summary
        assert "**Recommended Actions:**" in summary


class TestSuspiciousOutboundConnectionsDetection:
    def test_run_detection_true(self):
        mock_module = MagicMock()
        mock_module.data = [{"src": "1.1.1.1", "dst": "8.8.8.8"}]
        detection = SuspiciousOutboundConnectionsDetection([mock_module])
        assert detection.run_detection() is True

    def test_run_detection_false(self):
        mock_module = MagicMock()
        mock_module.data = []
        detection = SuspiciousOutboundConnectionsDetection([mock_module])
        assert detection.run_detection() is False

    def test_executive_summary_no_detection(self):
        mock_module = MagicMock()
        mock_module.data = []
        detection = SuspiciousOutboundConnectionsDetection([mock_module])
        assert detection.executive_summary == ""

    def test_executive_summary_with_detection(self):
        mock_module = MagicMock()
        mock_module.data = [
            {
                "src_endpoint.ip": "192.168.1.1",
                "dst_endpoint.ip": "8.8.8.8",
                "dst_endpoint.port": 53,
                "service.name": "DNS",
                "count": 3,
            },
            {
                "src_endpoint.ip": "10.0.0.1",
                "dst_endpoint.ip": "1.1.1.1",
                "dst_endpoint.port": 443,
                "service.name": "HTTPS",
                "count": 1,
            },
        ]
        detection = SuspiciousOutboundConnectionsDetection([mock_module])
        summary = detection.executive_summary
        assert "**FINDING: Suspicious Outbound Connections Detected**" in summary
        assert (
            "2 suspicious outbound connection(s) from OT devices were identified."
            in summary
        )
        assert "- 192.168.1.1 → 8.8.8.8:53 (DNS) - 3x" in summary
        assert "- 10.0.0.1 → 1.1.1.1:443 (HTTPS) - 1x" in summary
        assert "**Recommended Actions:**" in summary
