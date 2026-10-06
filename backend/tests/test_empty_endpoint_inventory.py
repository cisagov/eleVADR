"""Captures without eligible endpoint identities still produce valid reports."""

# Standard Python Libraries
import json

# Third-Party Libraries
import numpy as np
import pandas as pd
import pytest

# cisagov Libraries
from src.app.utils.analysis import Analyzer
from src.app.utils.report import DevicePanelModule, DevicesModule, Report


def make_analyzer(kind):
    """Build an analyzer with local, already-enriched traffic records."""
    row = {
        "connection_info.type_name": "unicast",
        "connection_info.direction_name": "outbound",
        "connection_info.protocol_ver_id": 4,
        "connection_info.activity_name": "SF",
        "connection_info.history": "ShADadFf",
        "src_endpoint.ip": "10.0.0.5",
        "dst_endpoint.ip": "10.0.0.6",
        "src_endpoint.mac": "aa:bb:cc:dd:ee:01",
        "dst_endpoint.mac": "aa:bb:cc:dd:ee:02",
        "src_endpoint.subnet": "10.0.0.0/24",
        "dst_endpoint.subnet": "10.0.0.0/24",
        "dst_endpoint.port": 53,
        "service.name": "DNS",
        "service.port_type": "KNOWN",
        "service.is_ot": False,
        "service.description": "DNS",
        "service.information_categories": "Name Service",
        "service.risk_categories": None,
        "service.risk_basis": None,
        "service.environment_exposure": "Internal",
        "service.protocol_posture": "Conditionally Risky",
    }
    if kind in ("broadcast", "multicast", "link-local"):
        row["connection_info.type_name"] = kind
    elif kind == "missing_mac":
        row["src_endpoint.mac"] = row["dst_endpoint.mac"] = None
    elif kind == "unspecified":
        row["src_endpoint.ip"] = row["dst_endpoint.ip"] = "0.0.0.0"
    traffic = pd.DataFrame([row])
    if kind == "empty":
        traffic = traffic.iloc[:0].copy()
    analyzer = object.__new__(Analyzer)
    analyzer.traffic_df = traffic
    analyzer.services_df = traffic[[c for c in traffic.columns if c.startswith("service.")]].drop_duplicates()
    analyzer.manufacturers_df = pd.DataFrame(columns=["manufacturer"])
    analyzer.endpoints_df = pd.DataFrame()
    return analyzer


@pytest.mark.parametrize("kind", ["empty", "broadcast", "multicast", "link-local", "missing_mac", "unspecified"])
def test_no_eligible_hosts_produce_zero_counts_and_empty_device_tables(kind):
    """Preserve a typed endpoint schema and all device-report consumers."""
    analyzer = make_analyzer(kind)
    before = analyzer.traffic_df.copy(deep=True)
    analyzer.endpoints_df_processing()
    assert analyzer.endpoints_df.empty
    assert analyzer.endpoints_df.index.name == "device.mac"
    assert analyzer.endpoints_df["device.is_ot"].dtype == np.dtype(bool)
    assert analyzer.endpoints_df["device.is_edge"].dtype == np.dtype(bool)
    assert DevicePanelModule(analyzer).data == {
        "hosts": 0,
        "ot_hosts": 0,
        "it_hosts": 0,
        "edge_hosts": 0,
        "ot_cross_segment": 0,
    }
    for column in ("device.is_ot", "device.is_edge"):
        assert DevicesModule(analyzer, "devices", lambda df: df[column]).data == []
    pd.testing.assert_frame_equal(before, analyzer.traffic_df)


@pytest.mark.parametrize("kind", ["empty", "broadcast", "missing_mac"])
def test_complete_report_serializes_without_any_discovered_endpoints(kind):
    """Exercise the real report modules and detections without Zeek or services."""
    analyzer = make_analyzer(kind)
    analyzer.endpoints_df_processing()
    report = Report(analyzer, report_id="empty-fixture")
    assert report.data["modules"]["device_panel"]["hosts"] == 0
    assert report.data["modules"]["ot_devices"] == []
    assert report.data["modules"]["it_devices"] == []
    assert report.data["modules"]["edge_devices"] == []
    json.dumps(report.data)


def test_nonempty_unicast_inventory_is_unchanged():
    """Valid private hosts retain their identities and classification."""
    analyzer = make_analyzer("unicast")
    analyzer.endpoints_df_processing()
    assert len(analyzer.endpoints_df) == 2
    assert analyzer.endpoints_df.index.tolist() == ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
    assert not analyzer.endpoints_df["device.is_ot"].any()
    assert not analyzer.endpoints_df["device.is_edge"].any()
    assert DevicePanelModule(analyzer).data["it_hosts"] == 2
