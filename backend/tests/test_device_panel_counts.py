"""Device-panel counts must match the report's disjoint IT device filter."""

from types import SimpleNamespace

import pandas as pd
import pytest

from src.app.utils.report import DevicePanelModule, DevicesModule


@pytest.mark.parametrize(
    "ot_flags,edge_flags,expected_it",
    [
        ([], [], 0),
        ([False], [False], 1),
        ([False], [True], 0),
        ([True], [False], 0),
        ([False, False], [False, True], 1),
        ([True, False, False], [False, True, False], 1),
        ([False, False, False], [False, False, True], 2),
        ([False, False, False], [False, True, True], 1),
        ([True, False, False, False], [True, False, False, True], 2),
        ([True, True], [False, True], 0),
    ],
)
def test_it_summary_counts_each_non_ot_non_edge_device_once(ot_flags, edge_flags, expected_it):
    """Edge devices already removed by the IT mask must not be subtracted again."""
    endpoints = pd.DataFrame(
        {
            "device.is_ot": pd.Series(ot_flags, dtype=bool),
            "device.is_edge": pd.Series(edge_flags, dtype=bool),
            "device.manufacturer": [f"device-{i}" for i in range(len(ot_flags))],
        }
    )
    before = endpoints.copy(deep=True)
    analyzer = SimpleNamespace(
        traffic_df=pd.DataFrame(),
        endpoints_df=endpoints,
        services_df=pd.DataFrame(),
        ot_cross_segment_communication_count=lambda: 7,
    )
    panel = DevicePanelModule(analyzer).data
    detail = DevicesModule(
        analyzer,
        name="it_devices",
        device_filter=lambda frame: (~frame["device.is_ot"]) & (~frame["device.is_edge"]),
    ).data
    assert panel["it_hosts"] == expected_it == len(detail)
    assert panel["hosts"] == len(ot_flags)
    assert panel["ot_hosts"] == sum(ot_flags)
    assert panel["edge_hosts"] == sum(edge_flags)
    assert panel["ot_cross_segment"] == 7
    pd.testing.assert_frame_equal(endpoints, before)


def test_adding_edge_devices_does_not_reduce_existing_it_count():
    """Unrelated edge-device growth cannot make IT devices disappear from totals."""
    for edge_count in range(5):
        frame = pd.DataFrame(
            {
                "device.is_ot": [False] * (3 + edge_count),
                "device.is_edge": [False] * 3 + [True] * edge_count,
            }
        )
        analyzer = SimpleNamespace(
            traffic_df=pd.DataFrame(),
            services_df=pd.DataFrame(),
            endpoints_df=frame,
            ot_cross_segment_communication_count=lambda: 0,
        )
        panel = DevicePanelModule(analyzer).data
        assert panel["it_hosts"] == 3
        assert panel["edge_hosts"] == edge_count
