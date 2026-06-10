"""Report assembly and module definitions for eleVADR output."""

# Standard Python Libraries
import ipaddress
from abc import ABC, abstractmethod
from collections import Counter
from collections.abc import Callable
from typing import Any, cast

# Third-Party Libraries
import numpy as np
import pandas as pd

from .analysis import Analyzer
from .utils import PortType, count_values_in_list_column

type JSONValue = dict[str, "JSONValue"] | list["JSONValue"] | str | int | float | bool | None


class Report:
    """Main report orchestrator class.

    Instantiates module classes and aggregates
    their data into a unified report structure.
    """

    REPORT_VERSION = "2.0"

    def __init__(self, analyzer: Analyzer, report_id: str | None = None):
        """Initialize report modules and assemble the top-level payload."""
        self.analyzer = analyzer
        self.report_id = report_id

        # Initialize all report modules
        modules_instances = [
            # Aggregate Analysis Modules
            ServicePanelModule(analyzer),
            DevicePanelModule(analyzer),
            ServiceRiskBreakdownModule(analyzer),
            ServiceCountModule(analyzer),
            RiskBasisBreakdownModule(analyzer),
            ExposureBreakdownModule(analyzer),
            ProtocolPostureModule(analyzer),
            ConnectionSuccessModule(analyzer),
            # Table Analysis Modules
            SuspiciousOutboundConnectionsModule(analyzer),
            OTcrossSegmentLinesModule(analyzer),
            DevicesModule(analyzer, name="ot_devices", device_filter=lambda df: df["device.is_ot"]),
            DevicesModule(
                analyzer,
                name="it_devices",
                device_filter=lambda df: (~df["device.is_ot"]) & (~df["device.is_edge"]),
            ),
            DevicesModule(
                analyzer,
                name="edge_devices",
                device_filter=lambda df: df["device.is_edge"],
            ),
            OTServicesModule(analyzer),
        ]
        self.modules = {module.name: module for module in modules_instances}

        # Initialize detection modules
        self.detections = [
            SuspiciousOutboundConnectionsDetection([self.modules["suspicious_outbound_connections_panel"]]),
            OTcrossSegmentDetection(
                [
                    self.modules["ot_cross_segment_lines_panel"],
                ]
            ),
        ]

        # Build executive summary from detections
        executive_summary = {}
        for detection in self.detections:
            if detection.run_detection():
                executive_summary[detection.name] = detection.executive_summary

        # Build the report data structure
        self.data: JSONValue = {
            "report_version": self.REPORT_VERSION,
            "report_id": self.report_id,
            "executive_summary": cast(JSONValue, executive_summary),
            "modules": {module_name: cast(JSONValue, module.data) for module_name, module in self.modules.items()},
            "arch_insights": {},
        }


class ReportModule(ABC):
    """Abstract base class for report modules."""

    def __init__(self, analyzer: Analyzer):
        """Store common dataframe references for concrete modules."""
        self.analyzer = analyzer
        self.traffic_df = analyzer.traffic_df
        self.endpoints_df = analyzer.endpoints_df
        self.services_df = analyzer.services_df
        self._data: object = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the identifier."""
        pass

    @abstractmethod
    def generate_data(self) -> object:
        """Generate module-specific data."""
        pass

    @property
    def data(self) -> object:
        """Lazy-load and cache data."""
        if self._data is None:
            self._data = self.generate_data()
        return self._data


#####
#
# Aggregate Analysis Modules
#
#####


class DevicePanelModule(ReportModule):
    """Device statistics module."""

    @property
    def name(self) -> str:
        """Return `device_panel`."""
        return "device_panel"

    def generate_data(self) -> dict[str, object]:
        """Summarize endpoint counts and OT cross\u2011segment communication.

        Returns
        -------
        dict
            {
                "hosts": total endpoint count,
                "ot_hosts": OT\u2011marked endpoint count,
                "it_hosts": IT\u2011only endpoint count,
                "edge_hosts": edge\u2011marked endpoint count,
                "ot_cross_segment": count of OT cross\u2011segment communications
            }

        """
        ot_hosts = self.endpoints_df[self.endpoints_df["device.is_ot"]]
        edge_hosts = self.endpoints_df[self.endpoints_df["device.is_edge"]]
        it_hosts = self.endpoints_df[(~self.endpoints_df["device.is_ot"]) & (~self.endpoints_df["device.is_edge"])]

        return {
            "hosts": len(self.endpoints_df),
            "ot_hosts": len(ot_hosts),
            "it_hosts": max(len(it_hosts) - len(edge_hosts), 0),
            "edge_hosts": len(edge_hosts),
            "ot_cross_segment": self.analyzer.ot_cross_segment_communication_count(),
        }


class ServicePanelModule(ReportModule):
    """Service overview statistics module."""

    @property
    def name(self) -> str:
        """Return `service_panel`."""
        return "service_panel"

    def generate_data(self) -> dict[str, object]:
        """Return a summary of service statistics.

        - known, unknown and OT services counts
        - risky services count
        """
        unknown_services = self.traffic_df[
            self.traffic_df["service.port_type"].isin(
                [
                    PortType.EPHEMERAL.name,
                    PortType.UNKNOWN.name,
                    PortType.UNKNOWN_PRIV.name,
                ]
            )
        ]
        # Known services
        known_services = self.traffic_df[self.traffic_df["service.port_type"].isin([PortType.KNOWN.name])]

        return {
            "num_known_services": len(known_services["service.name"].dropna().unique()),
            "num_ot_services": len(
                self.services_df[
                    self.services_df["service.information_categories"].apply(
                        lambda x: "Industrial Protocol" in x if isinstance(x, str) else False
                    )
                ]
            ),
            "num_risky_services": len(
                self.services_df[self.services_df["service.risk_categories"].notna()]["service.name"].unique()
            ),
            "num_unknown_services": len(unknown_services["service.name"].dropna().unique()),
        }


class ServiceRiskBreakdownModule(ReportModule):
    """Service risk categorization module."""

    @property
    def name(self) -> str:
        """Return `service_risk_breakdown_panel`."""
        return "service_risk_breakdown_panel"

    def generate_data(self) -> dict[str, object]:
        """Summarize service risk information.

        Returns
        -------
        dict
        {
        "risk_category_counts":  dict mapping risk category \u2192 occurrence count,
        "risk_category_services": dict mapping risk category \u2192 list of service names
        }

        """
        risk_category_counts = count_values_in_list_column(self.services_df, "service.risk_categories")
        risk_category_services = self.analyzer.service_category_map("service.risk_categories")

        return {
            "risk_category_counts": risk_category_counts,
            "risk_category_services": risk_category_services,
        }


class ServiceCountModule(ReportModule):
    """Service connection counts module."""

    @property
    def name(self) -> str:
        """Return `service_count_panel`."""
        return "service_count_panel"

    def generate_data(self) -> dict[str, object]:
        """Return the total number of distinct services observed in the traffic data.

        The method:
        * Splits the traffic frame into *known* and *unknown* services based on
        ``service.port_type`` (known, ephem\u2011eral, unknown, unknown\u2011priv).
        * Counts the unique, non\u2011null ``service.name`` values in each group.
        * Sums the two counts and returns the result.

        Returns:
        -------
        dict
            {
                "service_count": int  # total unique services (known + unknown)
            }

        Note:
        ----
        This routine depends on the ServicePanelModule data that the analyzer
        populates; the ``self.traffic_df`` must already contain the ``service.*``
        columns.

        """
        # Note: This module depends on ServicePanelModule data
        # We'll need to access the analyzer's services for counting
        unknown_services = self.traffic_df[
            self.traffic_df["service.port_type"].isin(
                [
                    PortType.EPHEMERAL.name,
                    PortType.UNKNOWN.name,
                    PortType.UNKNOWN_PRIV.name,
                ]
            )
        ]
        # Known services
        known_services = self.traffic_df[self.traffic_df["service.port_type"].isin([PortType.KNOWN.name])]

        service_total_count = len(known_services["service.name"].dropna().unique()) + len(
            unknown_services["service.name"].dropna().unique()
        )

        return {
            "service_count": service_total_count,
            "service_connections_count": self.analyzer.service_counts_in_traffic(),
        }


class RiskBasisBreakdownModule(ReportModule):
    """Breaks down observed services by risk basis (Observed vs Credible).

    Observed - directly used in compromises with evidence.
    Credible - known threat actor TTPs, not necessarily active now.
    """

    @property
    def name(self) -> str:
        """Return `risk_basis_breakdown_panel`."""
        return "risk_basis_breakdown_panel"

    def generate_data(self) -> dict[str, object]:
        """Return risk-basis counts and associated service names."""
        known_services = self.services_df[self.services_df["service.port_type"] == "KNOWN"]

        # Count services per basis value, excluding nulls
        basis_counts = known_services["service.risk_basis"].dropna().value_counts().to_dict()

        # Map each basis value to the services that carry it
        basis_service_map: dict[str, list[str]] = {}
        for _, row in known_services.iterrows():
            basis = row["service.risk_basis"]
            if isinstance(basis, str) and basis:
                basis_service_map.setdefault(basis, []).append(row["service.name"])

        return {
            "risk_basis_counts": basis_counts,
            "risk_basis_services": basis_service_map,
        }


class ExposureBreakdownModule(ReportModule):
    """Breaks down observed services by environment/exposure classification.

    External   - internet-facing or reachable from outside the org.
    Cross-Zone - traverses trust boundaries without broker/inspection.
    Internal   - confined within a protected cell/zone.
    """

    @property
    def name(self) -> str:
        """Return `exposure_breakdown_panel`."""
        return "exposure_breakdown_panel"

    def generate_data(self) -> dict[str, object]:
        """Return exposure counts and associated service names."""
        known_services = self.services_df[self.services_df["service.port_type"] == "KNOWN"]

        exposure_counts = known_services["service.environment_exposure"].dropna().value_counts().to_dict()

        exposure_service_map: dict[str, list[str]] = {}
        for _, row in known_services.iterrows():
            exposure = row["service.environment_exposure"]
            if isinstance(exposure, str) and exposure:
                exposure_service_map.setdefault(exposure, []).append(row["service.name"])

        return {
            "exposure_counts": exposure_counts,
            "exposure_services": exposure_service_map,
        }


class ConnectionSuccessModule(ReportModule):
    """Connection success vs failure breakdown based on Zeek conn.log."""

    @property
    def name(self) -> str:
        """Return `connection_success_panel`."""
        return "connection_success_panel"

    def generate_data(self) -> dict[str, object]:
        """Return connection success summary data and representative lines."""
        return {
            "summary": self.analyzer.connection_success_summary(),
            "connections": self.analyzer.connection_success_lines(limit=200),
        }


class ProtocolPostureModule(ReportModule):
    """Breaks down observed services by protocol posture.

    Inherently Risky   - clear-text or long-standing exploitation history.
    Conditionally Risky - secure if hardened, risky when exposed or tunnelled.
    """

    @property
    def name(self) -> str:
        """Return `protocol_posture_panel`."""
        return "protocol_posture_panel"

    def generate_data(self) -> dict[str, object]:
        """Return protocol-posture counts and associated service names."""
        known_services = self.services_df[self.services_df["service.port_type"] == "KNOWN"]

        posture_counts = known_services["service.protocol_posture"].dropna().value_counts().to_dict()

        posture_service_map: dict[str, list[str]] = {}
        for _, row in known_services.iterrows():
            posture = row["service.protocol_posture"]
            if isinstance(posture, str) and posture:
                posture_service_map.setdefault(posture, []).append(row["service.name"])

        return {
            "posture_counts": posture_counts,
            "posture_services": posture_service_map,
        }


#####
#
# Table Analysis Modules
#
#####


class SuspiciousOutboundConnectionsModule(ReportModule):
    """Suspicious outbound connections from OT devices module."""

    @property
    def name(self) -> str:
        """Return `suspicious_outbound_connections_panel`."""
        return "suspicious_outbound_connections_panel"

    def generate_data(self) -> list[dict[str, object]]:
        """Return grouped outbound OT connection records for reporting."""
        outbound_traffic = self.traffic_df[self.traffic_df["connection_info.direction_name"] == "outbound"]

        ot_join_col = "src_endpoint.mac" if "src_endpoint.mac" in outbound_traffic.columns else "dst_endpoint.mac"
        outbound_traffic_w_ot = outbound_traffic.merge(
            self.endpoints_df["device.is_ot"],
            left_on=ot_join_col,
            right_index=True,
            how="left",
        )

        display_cols = [
            "src_endpoint.ip",
            "dst_endpoint.ip",
            "dst_endpoint.port",
            "service.name",
        ]
        outbound_traffic_ot = outbound_traffic_w_ot[outbound_traffic_w_ot["device.is_ot"].fillna(False)][display_cols]
        return list(
            outbound_traffic_ot.groupby(display_cols, sort=False)
            .size()
            .reset_index(name="count")
            .to_dict(orient="records")
        )


class DevicesModule(ReportModule):
    """Generic devices module to list devices based on a filter."""

    def __init__(
        self,
        analyzer: Analyzer,
        name: str,
        device_filter: Callable[[pd.DataFrame], pd.Series],
    ):
        """Initialize the module with a report name and dataframe filter."""
        super().__init__(analyzer)
        self._name = name
        self.device_filter = device_filter

    @property
    def name(self) -> str:
        """Return the configured module name."""
        return self._name

    def generate_data(self) -> list[dict[str, Any]]:
        """Return filtered device records prepared for JSON serialization."""
        devices_df = self.endpoints_df[self.device_filter(self.endpoints_df)]

        device_columns = {
            "device.manufacturer": "manufacturer",
            "device.ipv4_ips": "ipv4_ips",
            "device.ipv6_ips": "ipv6_ips",
            "device.ipv4_subnets": "ipv4_subnets",
            "device.ipv6_subnets": "ipv6_subnets",
            "device.incoming_services": "incoming_services",
            "device.sent_services": "sent_services",
        }

        return self._prep_df_for_json(devices_df, device_columns)

    def _prep_df_for_json(self, df: pd.DataFrame, columns: dict[str, str]) -> list[dict[str, Any]]:
        """Prepare a dataframe for JSON serialization.

        Selects and renames columns before converting rows to records.
        """
        if df.empty:
            return []

        existing_cols = {k: v for k, v in columns.items() if k in df.columns}

        report_df = df[list(existing_cols.keys())].rename(columns=existing_cols)

        report_df = report_df.replace({np.nan: None})

        for column in report_df.columns:
            report_df[column] = report_df[column].apply(
                lambda value: sorted(value) if isinstance(value, set) else value
            )

        return list(report_df.astype(object).to_dict("records"))


# Removed OTManufacturersModule as it's being replaced
# class OTManufacturersModule(ReportModule):
#     """OT device manufacturers module"""
#
#     @property
#     def name(self) -> str:
#         return "ot_manufacturers"
#
#     def generate_data(self) -> dict:
#         return (
#             self.endpoints_df[self.endpoints_df["device.is_ot"]]["device.manufacturer"]
#             .value_counts()
#             .to_dict()
#         )


class OTServicesModule(ReportModule):
    """OT services/protocols module."""

    @property
    def name(self) -> str:
        """Return `ot_services`."""
        return "ot_services"

    def generate_data(self) -> list[dict[str, object]]:
        """Return service records tagged as industrial protocols."""
        return list(
            self.services_df[
                self.services_df["service.information_categories"].apply(
                    lambda x: "Industrial Protocol" in x if isinstance(x, str) else False
                )
            ].to_dict(orient="records")
        )


#####
#
#   Detection Modules
#
#####


class DetectionModule(ABC):
    """Abstract base class for detections based on report modules."""

    def __init__(self, report_modules: list[ReportModule]):
        """Store module dependencies used by a detection."""
        self.report_modules = report_modules
        self._data: object = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the identifier."""
        pass

    @property
    @abstractmethod
    def executive_summary(self) -> str:
        """Return the human-readable finding summary."""
        pass

    @abstractmethod
    def run_detection(self) -> bool:
        """Evaluate the detection against the available module data."""
        pass

    @property
    def data(self) -> object:
        """Lazy-load and cache data."""
        if self._data is None:
            self._data = self.generate_data()  # type: ignore[attr-defined]
        return self._data


class OTcrossSegmentLinesModule(ReportModule):
    """OT cross-segment communication lines module."""

    @property
    def name(self) -> str:
        """Return `ot_cross_segment_lines_panel`."""
        return "ot_cross_segment_lines_panel"

    @staticmethod
    def _is_excluded_cross_segment_ip(ip: object) -> bool:
        """Return whether an IP should be excluded from cross-segment reporting."""
        if not isinstance(ip, str) or not ip.strip():
            return True

        try:
            parsed_ip = ipaddress.ip_address(ip)
        except ValueError:
            return True

        return bool(
            getattr(parsed_ip, "is_multicast", False)
            or getattr(parsed_ip, "is_link_local", False)
            or ip == "255.255.255.255"
        )

    @classmethod
    def _preferred_ip_for_mac(cls, endpoints_df: pd.DataFrame, mac: str) -> str | None:
        """Return a stable preferred IP for a MAC, preferring IPv4 over IPv6."""
        if mac not in endpoints_df.index:
            return None

        endpoint = endpoints_df.loc[mac]
        if isinstance(endpoint, pd.DataFrame):
            endpoint = endpoint.iloc[0]

        for column in ("device.ipv4_ips", "device.ipv6_ips"):
            if column not in endpoint.index:
                continue
            ips = endpoint[column]
            if isinstance(ips, (list, tuple, np.ndarray)):
                for ip in ips:
                    if isinstance(ip, str) and ip.strip():
                        return str(ip)
        return None

    def generate_data(self) -> dict[str, list[dict[str, object]]]:
        """Return grouped OT cross-segment reporting data."""
        cross_seg_df = self.traffic_df.copy()

        empty_result: dict[str, list[dict[str, object]]] = {
            "lines": [],
            "subnet_pair_counts": [],
            "dst_subnet_counts": [],
            "ot_device_counts": [],
        }

        if cross_seg_df.empty:
            return empty_result

        ot_macs = set(self.endpoints_df[self.endpoints_df["device.is_ot"].fillna(False)].index)
        ot_mask = cross_seg_df["src_endpoint.mac"].isin(ot_macs) | cross_seg_df["dst_endpoint.mac"].isin(ot_macs)
        ot_cross_seg_df = cross_seg_df[ot_mask].copy()

        if ot_cross_seg_df.empty:
            return empty_result

        ot_cross_seg_df = ot_cross_seg_df[
            ot_cross_seg_df["src_endpoint.subnet"] != ot_cross_seg_df["dst_endpoint.subnet"]
        ].copy()

        if ot_cross_seg_df.empty:
            return empty_result

        ot_cross_seg_df = ot_cross_seg_df[
            ~ot_cross_seg_df["src_endpoint.ip"].apply(self._is_excluded_cross_segment_ip)
            & ~ot_cross_seg_df["dst_endpoint.ip"].apply(self._is_excluded_cross_segment_ip)
        ].copy()

        if ot_cross_seg_df.empty:
            return empty_result

        line_cols = [
            "src_endpoint.ip",
            "src_endpoint.subnet",
            "dst_endpoint.ip",
            "dst_endpoint.subnet",
            "dst_endpoint.port",
            "service.name",
        ]
        lines = list(
            ot_cross_seg_df[line_cols]
            .groupby(line_cols, sort=False)
            .size()
            .reset_index(name="count")
            .to_dict(orient="records")
        )

        subnet_pair_counts = list(
            ot_cross_seg_df.groupby(["src_endpoint.subnet", "dst_endpoint.subnet"], sort=False)
            .size()
            .reset_index(name="count")
            .to_dict(orient="records")
        )

        dst_subnet_counts = list(
            ot_cross_seg_df.groupby(["dst_endpoint.subnet"], sort=False)
            .size()
            .reset_index(name="count")
            .to_dict(orient="records")
        )

        ot_device_counter: Counter[str] = Counter()
        for _, row in ot_cross_seg_df.iterrows():
            for mac_column in ("src_endpoint.mac", "dst_endpoint.mac"):
                mac = row[mac_column]
                if mac in ot_macs:
                    ot_device_counter[mac] += 1

        ot_device_counts = [
            {
                "mac": mac,
                "ip": self._preferred_ip_for_mac(self.endpoints_df, mac),
                "count": count,
            }
            for mac, count in ot_device_counter.items()
        ]

        return {
            "lines": lines,
            "subnet_pair_counts": subnet_pair_counts,
            "dst_subnet_counts": dst_subnet_counts,
            "ot_device_counts": ot_device_counts,
        }


class SuspiciousOutboundConnectionsDetection(DetectionModule):
    """Detection: OT devices making suspicious outbound connections."""

    @property
    def name(self) -> str:
        """Return `suspicious_outbound_connections`."""
        return "suspicious_outbound_connections"

    @property
    def executive_summary(self) -> str:
        """Return a human-readable finding summary."""
        if not self.run_detection():
            return ""
        module = self.report_modules[0]
        data = module.data
        assert type(data) is list
        count = len(data)

        examples = ""
        example_lines = [
            (
                f"- {entry['src_endpoint.ip']} → "
                f"{entry['dst_endpoint.ip']}:{entry['dst_endpoint.port']} "
                f"({entry['service.name']}) - {entry['count']}x"
            )
            for entry in data
        ]
        examples = "\n".join(example_lines)

        return (
            "**FINDING: Suspicious Outbound Connections Detected**\n\n"
            f"{count} suspicious outbound connection(s) from OT devices were identified.\n\n"
            f"{examples}\n\n"
            "OT devices were observed making outbound connections to external hosts. "
            "This may indicate unauthorized communication or a compromised device.\n\n"
            "**Recommended Actions:**\n"
            "- Validate whether the destinations are approved external dependencies.\n"
            "- Review device ownership, change history, and recent operational intent.\n"
            "- Investigate for compromise, tunneling, or policy bypass if the traffic is unexpected."
        )

    def run_detection(self) -> bool:
        """Trip if any suspicious outbound OT connections are present."""
        module = self.report_modules[0]
        data = module.data
        return isinstance(data, list) and len(data) > 0


class OTcrossSegmentDetection(DetectionModule):
    """Detection: OT devices communicating across network segments."""

    @property
    def name(self) -> str:
        """Return `ot_cross_segment`."""
        return "ot_cross_segment"

    @property
    def executive_summary(self) -> str:
        """Return a human-readable finding summary."""
        if not self.run_detection():
            return ""
        module = self.report_modules[0]
        data = module.data
        lines = data.get("lines", []) if isinstance(data, dict) else []
        count = len(lines)

        examples = ""
        example_lines = [
            (
                f"- {entry['src_endpoint.ip']} → "
                f"{entry['dst_endpoint.ip']}:{entry['dst_endpoint.port']} "
                f"({entry['service.name']}) - {entry['count']}x"
            )
            for entry in lines
        ]
        if example_lines:
            examples = "\n".join(example_lines)

        return (
            "**FINDING: OT Cross-Segment Communications Detected**\n\n"
            f"{count} cross-segment communication example(s) involving OT assets were identified.\n\n"
            f"{examples}\n\n"
            "OT devices were observed communicating across network segments. "
            "This may indicate a misconfiguration or lateral movement attempt.\n\n"
            "**Recommended Actions:**\n"
            "- Validate whether the observed communications are expected for operations.\n"
            "- Review segmentation policy, firewall rules, and routing between the affected subnets.\n"
            "- Investigate potential unauthorized lateral movement if the traffic is unexpected."
        )

    def run_detection(self) -> bool:
        """Trip if any cross-segment OT lines are present."""
        module = self.report_modules[0]
        data = module.data
        return isinstance(data, dict) and isinstance(data.get("lines"), list) and len(data["lines"]) > 0
