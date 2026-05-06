"""Report assembly and module definitions for eleVADR output."""

# Standard Python Libraries
from abc import ABC, abstractmethod
import ipaddress
from typing import Any

# Third-Party Libraries
import numpy as np
import pandas as pd

from .analysis import Analyzer  # Ensure this line is present and correct
from .utils import PortType, count_values_in_list_column


class Report:
    """
    Main report orchestrator class.

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
            DevicesModule(
                analyzer, name="ot_devices", device_filter=lambda df: df["device.is_ot"]
            ),
            DevicesModule(
                analyzer,
                name="it_devices",
                device_filter=lambda df: (
                    (~df["device.is_ot"]) & (~df["device.is_edge"])
                ),
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
            SuspiciousOutboundConnectionsDetection(
                [self.modules["suspicious_outbound_connections_panel"]]
            ),
            OTcrossSegmentDetection(
                [
                    self.modules["ot_cross_segment_lines_panel"],
                ]
            ),
            # TestDetectionAlwaysTrips([]),  # Test detection doesn't need any modules
        ]

        # Build executive summary from detections
        executive_summary = {}
        for detection in self.detections:
            if detection.run_detection():
                executive_summary[detection.name] = detection.executive_summary

        # Build the report data structure
        self.data = {
            "report_version": self.REPORT_VERSION,
            "report_id": self.report_id,
            "executive_summary": executive_summary,
            "modules": {
                module_name: module.data for module_name, module in self.modules.items()
            },
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
        self._data = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the identifier."""
        pass

    @abstractmethod
    def generate_data(self):
        """Generate module-specific data."""
        pass

    @property
    def data(self):
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

    def generate_data(self) -> dict:
        """
        Summarize endpoint counts and OT cross‑segment communication.

        Returns
        -------
        dict
            {
                "hosts": total endpoint count,
                "ot_hosts": OT‑marked endpoint count,
                "it_hosts": IT‑only endpoint count,
                "edge_hosts": edge‑marked endpoint count,
                "ot_cross_segment": count of OT cross‑segment communications
            }
        """
        ot_hosts = self.endpoints_df[self.endpoints_df["device.is_ot"]]
        edge_hosts = self.endpoints_df[self.endpoints_df["device.is_edge"]]
        it_hosts = self.endpoints_df[
            (~self.endpoints_df["device.is_ot"])
            & (~self.endpoints_df["device.is_edge"])
        ]

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

    def generate_data(self) -> dict:
        """
        Return a summary of service statistics.

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
        known_services = self.traffic_df[
            self.traffic_df["service.port_type"].isin([PortType.KNOWN.name])
        ]

        return {
            "num_known_services": len(known_services["service.name"].dropna().unique()),
            "num_ot_services": len(
                self.services_df[
                    self.services_df["service.information_categories"].apply(
                        lambda x: (
                            "Industrial Protocol" in x if isinstance(x, str) else False
                        )
                    )
                ]
            ),
            "num_risky_services": len(
                self.services_df[self.services_df["service.risk_categories"].notna()][
                    "service.name"
                ].unique()
            ),
            "num_unknown_services": len(
                unknown_services["service.name"].dropna().unique()
            ),
        }


class ServiceRiskBreakdownModule(ReportModule):
    """Service risk categorization module."""

    @property
    def name(self) -> str:
        """Return `service_risk_breakdown_panel`."""
        return "service_risk_breakdown_panel"

    def generate_data(self) -> dict:
        """
        Summarize service risk information.

        Returns
        -------
        dict
        {
        "risk_category_counts":  dict mapping risk category → occurrence count,
        "risk_category_services": dict mapping risk category → list of service names
        }
        """
        risk_category_counts = count_values_in_list_column(
            self.services_df, "service.risk_categories"
        )
        risk_category_services = self.analyzer.service_category_map(
            "service.risk_categories"
        )

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

    def generate_data(self) -> dict:
        """
        Return the total number of distinct services observed in the traffic data.

        The method:
        * Splits the traffic frame into *known* and *unknown* services based on
        ``service.port_type`` (known, ephem‑eral, unknown, unknown‑priv).
        * Counts the unique, non‑null ``service.name`` values in each group.
        * Sums the two counts and returns the result.

        Returns
        -------
        dict
            {
                "service_count": int  # total unique services (known + unknown)
            }

        Note
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
        known_services = self.traffic_df[
            self.traffic_df["service.port_type"].isin([PortType.KNOWN.name])
        ]

        service_total_count = len(
            known_services["service.name"].dropna().unique()
        ) + len(unknown_services["service.name"].dropna().unique())

        return {
            "service_count": service_total_count,
            "service_connections_count": self.analyzer.service_counts_in_traffic(),
        }


class RiskBasisBreakdownModule(ReportModule):
    """
    Breaks down observed services by risk basis (Observed vs Credible).

    Observed - directly used in compromises with evidence.
    Credible - known threat actor TTPs, not necessarily active now.
    """

    @property
    def name(self) -> str:
        """Return `risk_basis_breakdown_panel`."""
        return "risk_basis_breakdown_panel"

    def generate_data(self) -> dict:
        """Return risk-basis counts and associated service names."""
        known_services = self.services_df[
            self.services_df["service.port_type"] == "KNOWN"
        ]

        # Count services per basis value, excluding nulls
        basis_counts = (
            known_services["service.risk_basis"].dropna().value_counts().to_dict()
        )

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
    """
    Breaks down observed services by environment/exposure classification.

    External   - internet-facing or reachable from outside the org.
    Cross-Zone - traverses trust boundaries without broker/inspection.
    Internal   - confined within a protected cell/zone.
    """

    @property
    def name(self) -> str:
        """Return `exposure_breakdown_panel`."""
        return "exposure_breakdown_panel"

    def generate_data(self) -> dict:
        """Return exposure counts and associated service names."""
        known_services = self.services_df[
            self.services_df["service.port_type"] == "KNOWN"
        ]

        exposure_counts = (
            known_services["service.environment_exposure"]
            .dropna()
            .value_counts()
            .to_dict()
        )

        exposure_service_map: dict[str, list[str]] = {}
        for _, row in known_services.iterrows():
            exposure = row["service.environment_exposure"]
            if isinstance(exposure, str) and exposure:
                exposure_service_map.setdefault(exposure, []).append(
                    row["service.name"]
                )

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

    def generate_data(self) -> dict:
        """Return connection success summary data and representative lines."""
        return {
            "summary": self.analyzer.connection_success_summary(),
            "connections": self.analyzer.connection_success_lines(limit=200),
        }


class ProtocolPostureModule(ReportModule):
    """
    Breaks down observed services by protocol posture.

    Inherently Risky   - clear-text or long-standing exploitation history.
    Conditionally Risky - secure if hardened, risky when exposed or tunnelled.
    """

    @property
    def name(self) -> str:
        """Return `protocol_posture_panel`."""
        return "protocol_posture_panel"

    def generate_data(self) -> dict:
        """Return protocol-posture counts and associated service names."""
        known_services = self.services_df[
            self.services_df["service.port_type"] == "KNOWN"
        ]

        posture_counts = (
            known_services["service.protocol_posture"].dropna().value_counts().to_dict()
        )

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

    def generate_data(self) -> list:
        """Return grouped outbound OT connection records for reporting."""
        outbound_traffic = self.traffic_df[
            self.traffic_df["connection_info.direction_name"] == "outbound"
        ]

        ot_join_col = (
            "src_endpoint.mac"
            if "src_endpoint.mac" in outbound_traffic.columns
            else "dst_endpoint.mac"
        )
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
        outbound_traffic_ot = outbound_traffic_w_ot[
            outbound_traffic_w_ot["device.is_ot"].fillna(False)
        ][display_cols]
        outbound_traffic_ot_counts = (
            outbound_traffic_ot.groupby(display_cols, sort=False)
            .size()
            .reset_index(name="count")
            .to_dict(orient="records")
        )

        return outbound_traffic_ot_counts


class DevicesModule(ReportModule):
    """Generic devices module to list devices based on a filter."""

    def __init__(self, analyzer: Analyzer, name: str, device_filter):
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

    def _prep_df_for_json(self, df: pd.DataFrame, columns: dict) -> list:
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

        return report_df.astype(object).to_dict("records")


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

    def generate_data(self) -> list:
        """Return service records tagged as industrial protocols."""
        return self.services_df[
            self.services_df["service.information_categories"].apply(
                lambda x: "Industrial Protocol" in x if isinstance(x, str) else False
            )
        ].to_dict(orient="records")


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
        self._data = None

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
    def run_detection(self):
        """Evaluate the detection against the available module data."""
        pass

    @property
    def data(self):
        """Lazy-load and cache data."""
        if self._data is None:
            self._data = self.generate_data()
        return self._data


class OTcrossSegmentLinesModule(ReportModule):
    """OT cross-segment communications with breakdowns."""

    @staticmethod
    def _preferred_ip_for_mac(endpoints_df: pd.DataFrame, mac: object) -> object:
        if not isinstance(mac, str) or mac not in endpoints_df.index:
            return None

        endpoint = endpoints_df.loc[mac]
        if isinstance(endpoint, pd.DataFrame):
            endpoint = endpoint.iloc[0]
        ipv4_ips = (
            endpoint.get("device.ipv4_ips") if isinstance(endpoint, pd.Series) else None
        )
        ipv6_ips = (
            endpoint.get("device.ipv6_ips") if isinstance(endpoint, pd.Series) else None
        )

        if isinstance(ipv4_ips, list) and len(ipv4_ips) > 0:
            return ipv4_ips[0]
        if isinstance(ipv6_ips, list) and len(ipv6_ips) > 0:
            return ipv6_ips[0]

        return None

    @property
    def name(self) -> str:
        """Return `ot_cross_segment_lines_panel`."""
        return "ot_cross_segment_lines_panel"

    @staticmethod
    def _is_excluded_cross_segment_ip(ip_value: object) -> bool:
        if not isinstance(ip_value, str) or not ip_value:
            return False

        try:
            ip_obj = ipaddress.ip_address(ip_value)
        except ValueError:
            return False

        if ip_obj.is_link_local or ip_obj.is_multicast:
            return True

        if ip_value == "255.255.255.255":
            return True

        if isinstance(
            ip_obj, ipaddress.IPv4Address
        ) and ip_obj == ipaddress.IPv4Address("255.255.255.255"):
            return True

        return False

    def generate_data(self) -> dict[str, object]:
        """Return OT cross-segment line items and supporting breakdowns."""
        df = self.traffic_df.copy()
        excluded_ip_mask = df["src_endpoint.ip"].apply(
            self._is_excluded_cross_segment_ip
        ) | df["dst_endpoint.ip"].apply(self._is_excluded_cross_segment_ip)
        df = df[~excluded_ip_mask]

        cross_segment = df[
            (df["dst_endpoint.subnet"].notna())
            & (df["src_endpoint.subnet"].notna())
            & (df["dst_endpoint.subnet"] != df["src_endpoint.subnet"])
        ]

        if cross_segment.empty:
            return {
                "lines": [],
                "subnet_pair_counts": [],
                "dst_subnet_counts": [],
                "ot_device_counts": [],
            }

        ot_macs = set(self.endpoints_df[self.endpoints_df["device.is_ot"]].index)

        # Keep rows where either endpoint is an OT asset.
        cross_segment = cross_segment[
            cross_segment["src_endpoint.mac"].isin(ot_macs)
            | cross_segment["dst_endpoint.mac"].isin(ot_macs)
        ]

        if cross_segment.empty:
            return {
                "lines": [],
                "subnet_pair_counts": [],
                "dst_subnet_counts": [],
                "ot_device_counts": [],
            }

        # Lines: group by src/dst ips and service name.
        lines_df = (
            cross_segment.groupby(
                [
                    "src_endpoint.ip",
                    "dst_endpoint.ip",
                    "dst_endpoint.port",
                    "service.name",
                ]
            )
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=False)
            .head(15)
        )

        lines = lines_df.replace({np.nan: None}).to_dict(orient="records")

        # Breakdown 1: subnet pairs.
        subnet_pair_df = (
            cross_segment.groupby(["src_endpoint.subnet", "dst_endpoint.subnet"])
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=False)
            .head(15)
            .rename(
                columns={
                    "src_endpoint.subnet": "src_subnet",
                    "dst_endpoint.subnet": "dst_subnet",
                }
            )
        )

        subnet_pair_counts = subnet_pair_df.replace({np.nan: None}).to_dict(
            orient="records"
        )

        # Breakdown 2: destination subnets.
        dst_subnet_df = (
            cross_segment.groupby(["dst_endpoint.subnet"])
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=False)
            .head(15)
            .rename(columns={"dst_endpoint.subnet": "dst_subnet"})
        )

        dst_subnet_counts = dst_subnet_df.replace({np.nan: None}).to_dict(
            orient="records"
        )

        # Breakdown 3: per-OT-device flow counts using IP display values
        # instead of MAC addresses.
        ot_src_cross_segment = cross_segment[
            cross_segment["src_endpoint.mac"].isin(ot_macs)
        ].copy()
        ot_src_cross_segment["src_device_ip"] = ot_src_cross_segment[
            "src_endpoint.mac"
        ].apply(lambda mac: self._preferred_ip_for_mac(self.endpoints_df, mac))
        ot_src_cross_segment = ot_src_cross_segment[
            ot_src_cross_segment["src_device_ip"].notna()
        ]

        ot_device_df = (
            ot_src_cross_segment.groupby(["src_device_ip"])
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=False)
            .head(15)
        )
        ot_device_counts = ot_device_df.replace({np.nan: None}).to_dict(
            orient="records"
        )

        return {
            "lines": lines,
            "subnet_pair_counts": subnet_pair_counts,
            "dst_subnet_counts": dst_subnet_counts,
            "ot_device_counts": ot_device_counts,
        }


class OTcrossSegmentDetection(DetectionModule):
    """Detection module that identifies OT cross-segment communications."""

    @property
    def name(self) -> str:
        """Return `ot_cross_segment_alert`."""
        return "ot_cross_segment_alert"

    def run_detection(self) -> bool:
        """Return whether OT cross-segment communication was detected."""
        payload = self.report_modules[0].data
        lines = payload.get("lines", []) if isinstance(payload, dict) else []
        return len(lines) > 0

    @property
    def executive_summary(self) -> str:
        """Return a human-readable summary of the detection findings."""
        payload = self.report_modules[0].data
        lines = payload.get("lines", []) if isinstance(payload, dict) else []
        if len(lines) == 0:
            return ""

        num_examples = len(lines)

        summary = (
            "**FINDING: OT Cross-Segment Communications Detected**\n\n"
            f"{num_examples} cross-segment communication example(s) "
            "involving OT assets were identified. "
            "Traffic traversing different Subnet/VLAN boundaries can indicate "
            "missing segmentation controls or unauthorized lateral movement.\n\n"
            "**Example Communications:**\n"
        )

        for conn in lines[:5]:
            src_ip = conn.get("src_endpoint.ip") or "Unknown"
            dst_ip = conn.get("dst_endpoint.ip") or "Unknown"
            dst_port = conn.get("dst_endpoint.port") or "Unknown"
            service = conn.get("service.name") or "Unknown"
            count = conn.get("count") or 1
            summary += f"- {src_ip} → {dst_ip}:{dst_port} ({service}) - {count}x\n"

        if num_examples > 5:
            summary += f"- ... and {num_examples - 5} more\n"

        summary += (
            "\n**Recommended Actions:**\n"
            "- Validate approved OT-to-other-segment flows using firewall/ACL rules\n"
            "- Review segmentation policy (Subnet/VLAN boundaries) and verify "
            "enforcement on boundary devices\n"
            "- Investigate whether any OT assets should be isolated or forced "
            "through controlled jump points\n"
            "- Implement monitoring/alerting for anomalous "
            "cross-segment lateral traffic\n"
        )

        return summary


class SuspiciousOutboundConnectionsDetection(DetectionModule):
    """Flag suspicious outbound connections initiated by OT devices."""

    @property
    def name(self) -> str:
        """Return `suspicious_outbound_connections_detection`."""
        return "suspicious_outbound_connections_detection"

    def run_detection(self) -> bool:
        """Return whether suspicious outbound OT connections exist."""
        # Access the SuspiciousOutboundConnectionsModule directly
        connections = self.report_modules[0].data
        return len(connections) > 0

    @property
    def executive_summary(self) -> str:
        """Generate an executive summary with findings and guidance."""
        if not self.run_detection():
            return ""

        # Get the suspicious connections data from the module
        connections = self.report_modules[0].data

        if not connections:
            return ""

        num_connections = len(connections)

        # Build the executive summary
        summary = f"""**FINDING: Suspicious Outbound Connections Detected**

{num_connections} suspicious outbound connection(s) from OT devices were identified.
OT devices typically should not initiate outbound connections, which may
indicate unauthorized access, data exfiltration, or compromised devices.

**Affected Connections:**
"""

        # Add details about the connections
        for conn in connections[:5]:  # Show up to 5 examples
            src_ip = conn.get("src_endpoint.ip", "Unknown")
            dst_ip = conn.get("dst_endpoint.ip", "Unknown")
            dst_port = conn.get("dst_endpoint.port", "Unknown")
            service = conn.get("service.name", "Unknown")
            count = conn.get("count", 1)
            summary += f"- {src_ip} → {dst_ip}:{dst_port} ({service}) - {count}x\n"

        if num_connections > 5:
            summary += f"- ... and {num_connections - 5} more\n"

        summary += """
**Recommended Actions:**
- Investigate identified connections for legitimacy
- Implement egress filtering to block unauthorized outbound traffic from OT networks
- Review network segmentation and firewall rules
- Deploy monitoring/alerting for anomalous outbound patterns
- Establish baseline communication patterns and enforce allow-lists
"""

        return summary
