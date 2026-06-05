"""Core PCAP analysis logic for eleVADR."""

# Standard Python Libraries
import ipaddress
import json
import subprocess
from pathlib import Path
from typing import Any, cast

# Third-Party Libraries
import numpy as np
import pandas as pd
from zat.log_to_dataframe import LogToDataFrame

from .utils import (
    FilePathInfo,
    PortType,
    check_ip_version,
    connection_type_processing,
    is_communicating_with_ot_hosts,
    is_public_ip,
    is_using_ot_services,
    service_processing,
    set_manufacturers,
    subnet_membership,
    traffic_direction,
)


class PcapParser:
    """Process PCAP files using Zeek and create traffic dataframe."""

    def __init__(self, file_path_info: FilePathInfo):
        """Initialize parser state and build empty analysis dataframes."""
        self.file_path_info = file_path_info
        if file_path_info.path_to_pcap is None:
            raise ValueError("path_to_pcap must be provided.")
        if file_path_info.path_to_zeek is None:
            raise ValueError("path_to_zeek must be provided.")
        self.pcap_filename = Path(file_path_info.path_to_pcap).stem
        self.upload_output_zeek_dir = Path(file_path_info.path_to_zeek) / self.pcap_filename

        # Define traffic dataframe schema
        traffic_df_schema = {
            # 0 - UNK, 4 - IPv4, 6 - IPv6, 99 - other
            "connection_info.protocol_ver_id": int,
            # CUSTOM: unicast, multicast, broadcast
            "connection_info.type_name": str,
            # None, inbound, outbound, lateral, other
            "connection_info.direction_name": str,
            # tcp, udp, other IANA assigned L4 protocol
            "connection_info.protocol_name": str,
            "connection_info.activity_name": str,
            "connection_info.history": str,
            "dst_endpoint.ip": str,
            "dst_endpoint.mac": str,  # CONDITIONAL
            "dst_endpoint.port": int,
            "dst_endpoint.subnet": str,  # CUSTOM
            "src_endpoint.ip": str,
            "src_endpoint.mac": str,  # CONDITIONAL
            "src_endpoint.port": int,
            "src_endpoint.subnet": str,  # CUSTOM
            "service.name": str,  # CUSTOM
            "service.port_type": str,  # CUSTOM - see utils.PortTypes
            "service.description": str,  # CUSTOM
            "service.information_categories": str,  # CUSTOM
            # CUSTOM
            "service.risk_categories": str,
            # CUSTOM - Observed | Credible
            "service.risk_basis": str,
            # CUSTOM - External | Cross-Zone | Internal
            "service.environment_exposure": str,
            # CUSTOM - Inherently Risky | Conditionally Risky
            "service.protocol_posture": str,
            "service.is_ot": bool,  # CUSTOM
        }
        self.traffic_df = pd.DataFrame(columns=traffic_df_schema.keys()).astype(traffic_df_schema)

    def parse(self) -> None:
        """Execute Zeek processing and load results into dataframes."""
        # Process PCAP using Zeek
        self.zeekify()

        # Convert Zeek conn.log to pandas DataFrame
        conn_log_path = self.upload_output_zeek_dir / "conn.log"

        log_to_df = LogToDataFrame()
        try:
            conn_df = log_to_df.create_dataframe(str(conn_log_path))
        except Exception as exc:
            raise OSError(f"Could not read/access zeek log file: {conn_log_path}") from exc

        # Map Zeek columns to traffic_df schema
        conn_df_mappings = {
            "proto": "connection_info.protocol_name",
            "id.orig_h": "src_endpoint.ip",
            "id.orig_p": "src_endpoint.port",
            "id.resp_h": "dst_endpoint.ip",
            "id.resp_p": "dst_endpoint.port",
            "orig_l2_addr": "src_endpoint.mac",
            "resp_l2_addr": "dst_endpoint.mac",
            "conn_state": "connection_info.activity_name",
            "history": "connection_info.history",
        }
        mapped_conn_df = conn_df.rename(columns=conn_df_mappings)
        available_columns = [column for column in conn_df_mappings.values() if column in mapped_conn_df]
        if available_columns:
            self.traffic_df = pd.concat(
                [self.traffic_df, mapped_conn_df[available_columns]],
                ignore_index=True,
            )

        # Initialize endpoint and services dataframes
        endpoints_df_schema = {
            "device.mac": str,
            "device.manufacturer": str,  # CUSTOM
            "device.is_ot": bool,
            "device.is_edge": bool,
            "device.ipv4_ips": str,
            "device.ipv6_ips": str,
            "device.ip_scope": str,  # CUSTOM: private or global
            "device.ipv4_subnets": str,
            "device.ipv6_subnets": str,  # will we ever use this?
            # CUSTOM: 0 - UNK, 4 - IPv4, 6 - IPv6, 46 - IPv4 and IPv6, 99 - other
            "device.protocol_ver_id": int,
            "device.sent_services": object,
            "device.incoming_services": object,
            "device.sent_ports": object,
            "device.incoming_ports": object,
        }
        self.endpoints_df = pd.DataFrame(columns=endpoints_df_schema.keys()).astype(endpoints_df_schema)

        services_df_schema = {
            "service.name": str,  # CUSTOM
            "service.port_type": str,  # CUSTOM - see utils.PortTypes
            "service.description": str,  # CUSTOM
            "service.information_categories": str,  # CUSTOM
            "service.risk_categories": str,  # CUSTOM
            "service.risk_basis": str,  # CUSTOM - Observed | Credible
            # CUSTOM - External | Cross-Zone | Internal
            "service.environment_exposure": str,
            # CUSTOM - Inherently Risky | Conditionally Risky
            "service.protocol_posture": str,
            "service.is_ot": bool,  # CUSTOM
        }
        self.services_df = pd.DataFrame(columns=services_df_schema.keys()).astype(services_df_schema)

    def zeekify(self) -> None:
        """Execute PCAP analysis using Zeek."""
        # Create output directory if needed
        if not self.upload_output_zeek_dir.exists():
            self.upload_output_zeek_dir.mkdir(parents=True)

        # Run default Zeek processing
        subprocess.check_output(
            [
                "zeek",
                "-r",
                str(self.file_path_info.path_to_pcap),
                f"Log::default_logdir={self.upload_output_zeek_dir}",
            ]
        )

        # Run mac_logging Zeek script
        if self.file_path_info.path_to_zeek_scripts is None:
            raise ValueError("path_to_zeek_scripts must be provided.")
        mac_script = Path(self.file_path_info.path_to_zeek_scripts) / "mac_logging.zeek"
        subprocess.check_output(
            [
                "zeek",
                "-r",
                str(self.file_path_info.path_to_pcap),
                str(mac_script),
                f"Log::default_logdir={self.upload_output_zeek_dir}",
            ]
        )


class Analyzer:
    """Enrich traffic data with analysis and generate endpoint/service dataframes."""

    ports_df: pd.DataFrame
    port_risk_df: pd.DataFrame
    manufacturers_df: pd.DataFrame

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

        if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj == ipaddress.IPv4Address("255.255.255.255"):
            return True

        return False

    def _cross_segment_traffic_df(self) -> pd.DataFrame:
        excluded_ip_mask = self.traffic_df["src_endpoint.ip"].apply(
            self._is_excluded_cross_segment_ip
        ) | self.traffic_df["dst_endpoint.ip"].apply(self._is_excluded_cross_segment_ip)

        return self.traffic_df[
            ~excluded_ip_mask
            & self.traffic_df["src_endpoint.subnet"].notna()
            & self.traffic_df["dst_endpoint.subnet"].notna()
            & (self.traffic_df["dst_endpoint.subnet"] != self.traffic_df["src_endpoint.subnet"])
        ]

    def __init__(
        self,
        traffic_df: pd.DataFrame,
        endpoints_df: pd.DataFrame,
        services_df: pd.DataFrame,
        file_path_info: FilePathInfo,
    ):
        """Initialize analyzer state and derive all report-facing dataframes."""
        self.traffic_df = traffic_df
        self.endpoints_df = endpoints_df
        self.services_df = services_df
        self.file_path_info = file_path_info

        self.get_assessor_data()
        self.traffic_df_processing()
        self.endpoints_df_processing()
        self.services_df_processing()

    def traffic_df_processing(self) -> None:
        """Add IP, conn type, direction, subnet, service info to traffic."""
        if self.traffic_df.empty:
            return

        required_cols = {
            "src_endpoint.ip",
            "dst_endpoint.ip",
            "dst_endpoint.port",
        }
        missing = required_cols - set(self.traffic_df.columns)
        if missing:
            # If the caller supplied a traffic dataframe without the expected
            # schema we bail out silently – the Analyzer will still be usable
            # for modules that only need endpoint/service data.
            return

        # IP version (4, 6 or 99 for invalid)
        self.traffic_df["connection_info.protocol_ver_id"] = self.traffic_df["src_endpoint.ip"].apply(check_ip_version)

        # Connection type (multicast, broadcast, unicast)
        self.traffic_df["connection_info.type_name"] = self.traffic_df["dst_endpoint.ip"].apply(
            connection_type_processing
        )

        # Traffic direction (inbound, outbound, lateral, external, or other)
        self.traffic_df["connection_info.direction_name"] = self.traffic_df.apply(traffic_direction, axis=1)

        # If the dataframe became empty after the above transformations
        # (e.g., all rows were filtered out by a custom ``traffic_direction``)
        # we stop further processing.
        if self.traffic_df.empty:
            return

        # Subnet membership – adds ``src_endpoint.subnet`` and ``dst_endpoint.subnet``
        self.traffic_df = self.traffic_df.apply(subnet_membership, axis=1)

        # Service mapping and risk categorisation.
        # ``service_processing`` expects the ports and risk dataframes to be
        # present – they are populated in ``get_assessor_data``.
        self.traffic_df = self.traffic_df.apply(
            lambda row: service_processing(row, self.ports_df, self.port_risk_df),
            axis=1,
        )

    def endpoints_df_processing(self) -> None:
        """Create endpoint DataFrame with device info, IPs, services, OT label."""
        # Create a unified list of all observed IP-MAC-Subnet relationships

        def _filter_specified_ips(df: pd.DataFrame, ip_col: str) -> pd.DataFrame:
            return df[~df[ip_col].isin(["0.0.0.0", "::"])]

        unicast_traffic = self.traffic_df[self.traffic_df["connection_info.type_name"] == "unicast"]

        src = unicast_traffic[["src_endpoint.ip", "src_endpoint.mac", "src_endpoint.subnet"]].rename(
            columns={
                "src_endpoint.ip": "ip",
                "src_endpoint.mac": "mac",
                "src_endpoint.subnet": "subnet",
            }
        )
        dst = unicast_traffic[["dst_endpoint.ip", "dst_endpoint.mac", "dst_endpoint.subnet"]].rename(
            columns={
                "dst_endpoint.ip": "ip",
                "dst_endpoint.mac": "mac",
                "dst_endpoint.subnet": "subnet",
            }
        )

        src = _filter_specified_ips(src, "ip")
        dst = _filter_specified_ips(dst, "ip")

        ip_map = pd.concat([src, dst]).dropna(subset=["ip", "mac"]).drop_duplicates()
        ip_map = ip_map[~ip_map["ip"].isin(["0.0.0.0", "::"])]

        if ip_map.empty:
            self.endpoints_df = pd.DataFrame().set_index(pd.Index([], name="device.mac"))
            return

        # Filter traffic to exclude unspecified IPs
        # before grouping to avoid count inflation
        filtered_traffic = unicast_traffic[
            ~unicast_traffic["src_endpoint.ip"].isin(["0.0.0.0", "::"])
            & ~unicast_traffic["dst_endpoint.ip"].isin(["0.0.0.0", "::"])
        ]

        incoming_services = filtered_traffic.groupby("dst_endpoint.ip").agg(
            incoming_services=("service.name", lambda x: set(x.dropna())),
            incoming_ports=("dst_endpoint.port", lambda x: set(x.dropna())),
        )
        sent_services = filtered_traffic.groupby("src_endpoint.ip").agg(
            sent_services=("service.name", lambda x: set(x.dropna())),
            sent_ports=("dst_endpoint.port", lambda x: set(x.dropna())),
        )
        ip_services = pd.concat([incoming_services, sent_services], axis=1)

        # Join the IP-MAC-Subnet map with the IP-Service map
        ip_details = ip_map.set_index("ip").join(ip_services).reset_index()

        # Define a helper for aggregating lists/sets of items
        def agg_unique_items(series: pd.Series) -> list[Any] | float:
            items: set[Any] = set()
            for item in series.dropna():
                if isinstance(item, (list, set)):
                    items.update(item)
                else:
                    items.add(item)
            return sorted(items) if items else np.nan

        # Aggregation function to apply to each MAC address group
        def agg_by_mac(group: pd.DataFrame) -> pd.Series:
            res: dict[str, object] = {}
            all_ips = group["ip"].dropna().unique()
            all_ips = [ip for ip in all_ips if ip not in ("0.0.0.0", "::")]
            res["device.ipv4_ips"] = [ip for ip in all_ips if check_ip_version(ip) == 4] or np.nan
            res["device.ipv6_ips"] = [ip for ip in all_ips if check_ip_version(ip) == 6] or np.nan

            ipv4_subnets = (
                group[group["ip"].apply(lambda x: check_ip_version(x) == 4 and x not in ("0.0.0.0", "::"))]["subnet"]
                .dropna()
                .unique()
            )

            ipv6_subnets = (
                group[group["ip"].apply(lambda x: check_ip_version(x) == 6 and x not in ("0.0.0.0", "::"))]["subnet"]
                .dropna()
                .unique()
            )

            res["device.ipv4_subnets"] = list(ipv4_subnets) if len(ipv4_subnets) > 0 else np.nan
            res["device.ipv6_subnets"] = list(ipv6_subnets) if len(ipv6_subnets) > 0 else np.nan

            res["device.incoming_services"] = agg_unique_items(group["incoming_services"])
            res["device.sent_services"] = agg_unique_items(group["sent_services"])
            res["device.incoming_ports"] = agg_unique_items(group["incoming_ports"])
            res["device.sent_ports"] = agg_unique_items(group["sent_ports"])

            return pd.Series(res)

        grouped_ip_details = ip_details.groupby("mac", group_keys=False)
        endpoints_df = (
            grouped_ip_details.apply(agg_by_mac, include_groups=False)
            .reset_index()
            .rename(columns={"mac": "device.mac"})
        )

        endpoints_df = endpoints_df[endpoints_df["device.ipv4_ips"].notna() | endpoints_df["device.ipv6_ips"].notna()]

        # Add manufacturer information
        manufacturers_df = getattr(
            self,
            "manufacturers_df",
            pd.DataFrame(columns=["manufacturer"]),
        )
        endpoints_df = endpoints_df.apply(lambda row: set_manufacturers(row, manufacturers_df), axis=1)

        self.endpoints_df = endpoints_df.set_index("device.mac")

        # --- Classification Stage --- #
        self.endpoints_df["device.is_ot"] = self.endpoints_df.apply(
            lambda row: is_using_ot_services(row, self.traffic_df), axis=1
        )

        ot_device_rows = self.endpoints_df[self.endpoints_df["device.is_ot"]]
        ot_ips = set(ot_device_rows["device.ipv4_ips"].explode().dropna()) | set(
            ot_device_rows["device.ipv6_ips"].explode().dropna()
        )

        self.endpoints_df = self.endpoints_df.apply(
            lambda row: is_communicating_with_ot_hosts(row, self.traffic_df, ot_ips),
            axis=1,
        )

        self.endpoints_df["device.is_edge"] = self.endpoints_df.apply(
            lambda row: any(
                is_public_ip(ip)
                for ip in (
                    (row.get("device.ipv4_ips") if isinstance(row.get("device.ipv4_ips"), list) else [])
                    + (row.get("device.ipv6_ips") if isinstance(row.get("device.ipv6_ips"), list) else [])
                )
            ),
            axis=1,
        )

    def services_df_processing(self) -> None:
        """Prepare ``self.services_df`` from ``self.traffic_df``.

        - copy only the service‑related columns,
        - convert category fields to comma‑separated strings,
        - deduplicate by ``service.name`` keeping the row with the most populated
        ``service.risk_categories``.
        """
        if self.traffic_df.empty:
            self.services_df = pd.DataFrame(columns=self.services_df.columns)
            return

        self.services_df = self.traffic_df[self.services_df.columns].copy()

        # Ensure category columns are strings for deduplication and display.
        # Parquet can sometimes deserialize lists as numpy arrays, which are unhashable.
        category_cols = [
            "service.information_categories",
            "service.risk_categories",
        ]
        for col in category_cols:
            self.services_df[col] = self.services_df[col].apply(
                lambda x: ", ".join(x) if isinstance(x, (list, np.ndarray)) else (x if pd.notna(x) else None)
            )

        # Deduplicate by service name, preferring rows with the most populated fields.
        # Sort so that rows with risk_categories
        # populated sort before nulls, then keep first.
        self.services_df = self.services_df.sort_values("service.risk_categories", na_position="last").drop_duplicates(
            subset=["service.name"], keep="first"
        )

        self.services_df = self.services_df.replace({np.nan: None})

    def get_assessor_data(self) -> None:
        """Load reference data: ports, port risks, and manufacturers."""
        parquet_files: dict[str, str] = {
            "ports_df": "ports.parquet",
            "port_risk_df": "port_risk_v2.parquet",
        }
        json_files: dict[str, str] = {
            "manufacturers_df": "latest_oui_lookup.json",
        }

        for attr_name, filename in parquet_files.items():
            if self.file_path_info.path_to_assessor_data is None:
                raise ValueError("path_to_assessor_data must be provided.")
            file_path = Path(self.file_path_info.path_to_assessor_data) / filename
            try:
                setattr(self, attr_name, pd.read_parquet(file_path, engine="pyarrow"))
            except Exception as e:
                raise ValueError(f"Error loading {filename}: {e}") from e

        for attr_name, filename in json_files.items():
            if self.file_path_info.path_to_assessor_data is None:
                raise ValueError("path_to_assessor_data must be provided.")
            file_path = Path(self.file_path_info.path_to_assessor_data) / filename
            try:
                with open(file_path) as f:
                    json_payload = json.load(f)
                setattr(
                    self,
                    attr_name,
                    pd.DataFrame.from_dict(json_payload, orient="index"),
                )
            except Exception as e:
                raise ValueError(f"Error loading {filename}: {e}") from e

        # Special handling for manufacturers dataframe
        self.manufacturers_df.index = self.manufacturers_df.index.rename("oui")
        if 0 in self.manufacturers_df.columns:
            self.manufacturers_df = self.manufacturers_df.rename(columns={0: "manufacturer"})
        elif "manufacturer" not in self.manufacturers_df.columns:
            first_column = self.manufacturers_df.columns[0]
            self.manufacturers_df = self.manufacturers_df.rename(columns={first_column: "manufacturer"})

    # Report Analysis Methods

    def ot_cross_segment_communication_count(self) -> int:
        """Count OT devices communicating across network segments."""
        ot_macs = set(self.endpoints_df[self.endpoints_df["device.is_ot"]].index)
        cross_segment_traffic = self._cross_segment_traffic_df()
        cross_segment_macs = set(
            pd.concat(
                [
                    cross_segment_traffic["src_endpoint.mac"],
                    cross_segment_traffic["dst_endpoint.mac"],
                ]
            )
            .dropna()
            .unique()
        )
        return len(ot_macs.intersection(cross_segment_macs))

    def service_counts_in_traffic(self) -> dict[str, object]:
        """Count occurrences of known and unknown services."""
        unknown_services = self.traffic_df[
            self.traffic_df["service.port_type"].isin(
                [
                    PortType.EPHEMERAL.name,
                    PortType.UNKNOWN.name,
                    PortType.UNKNOWN_PRIV.name,
                ]
            )
        ]
        known_services = self.traffic_df[self.traffic_df["service.port_type"].isin([PortType.KNOWN.name])]

        # For known services, group by name and port
        if not known_services.empty:
            known_service_counts = (
                known_services.groupby(["service.name", "dst_endpoint.port"]).size().reset_index(name="count")
            )
            known_service_counts = known_service_counts.rename(
                columns={"service.name": "name", "dst_endpoint.port": "port"}
            )
            named_service_counts = known_service_counts.to_dict("records")
        else:
            named_service_counts = []

        # For unknown services, the name already
        # includes the port, so value_counts is fine
        unnamed_service_counts = unknown_services["service.name"].value_counts().to_dict()
        return {
            "known_services": named_service_counts,
            "unknown_services": unnamed_service_counts,
        }

    def service_category_map(self, category: str) -> dict[str, list[str]]:
        """Map service categories to service names."""
        category_map: dict[str, list[str]] = {}
        for _, row in self.services_df.iterrows():
            categories = row[category]
            if isinstance(categories, str) and categories.strip():
                split_categories = [cat.strip() for cat in categories.split(",") if cat.strip()]
                for cat in split_categories:
                    service_names = category_map.setdefault(cat, [])
                    service_name = row["service.name"]
                    if service_name and service_name not in service_names:
                        service_names.append(service_name)
        return category_map

    @staticmethod
    def _is_successful_conn_state(conn_state: object) -> bool:
        """Classify a Zeek conn_state as successful or unsuccessful.

        Policy used by this report:
        - SF => successful
        - all other conn_state values => unsuccessful

        Rationale:
        - conn_state is Zeek's normalized connection outcome and is the best primary
          field for high-level reporting.
        - history is included for analyst drill-down, but not used as the primary
          classification signal.
        - States such as S0, REJ, RSTO, RSTR, SH, SHR, and OTH remain visible in
          the by_state breakdown even though they are rolled into the
          unsuccessful_count summary bucket.
        """
        return conn_state == "SF"

    def connection_success_summary(self) -> dict[str, object]:
        """Summarize success vs unsuccessful connections from Zeek conn_state.

        Primary source:
        - traffic_df["connection_info.activity_name"] from Zeek conn_state

        Supplementary detail:
        - traffic_df["connection_info.history"] from Zeek history
        """
        if self.traffic_df.empty:
            return {
                "successful_count": 0,
                "unsuccessful_count": 0,
                "by_state": {},
            }

        state_col = "connection_info.activity_name"
        if state_col not in self.traffic_df.columns:
            raise KeyError(f"traffic_df is missing expected column: {state_col}")

        state_series = self.traffic_df[state_col]
        by_state: dict[str, int] = state_series.dropna().value_counts().to_dict()

        successful_mask = state_series.apply(self._is_successful_conn_state)
        successful_count = int(successful_mask.sum())
        unsuccessful_count = int((~successful_mask).sum())

        return {
            "successful_count": successful_count,
            "unsuccessful_count": unsuccessful_count,
            "by_state": by_state,
        }

    def connection_success_lines(self, limit: int = 200) -> list[dict[str, object]]:
        """Return per-connection rows annotated with success/failure.

        Limit is applied after deterministic sorting.
        """
        if limit <= 0:
            return []

        if self.traffic_df.empty:
            return []

        required_cols = {
            "src_endpoint.ip",
            "dst_endpoint.ip",
            "dst_endpoint.port",
            "connection_info.activity_name",
        }
        missing = required_cols - set(self.traffic_df.columns)
        if missing:
            raise KeyError(f"traffic_df is missing expected columns: {sorted(missing)}")

        selected_columns = [
            "src_endpoint.ip",
            "dst_endpoint.ip",
            "dst_endpoint.port",
            "connection_info.activity_name",
        ]
        if "connection_info.history" in self.traffic_df.columns:
            selected_columns.append("connection_info.history")

        df = self.traffic_df[selected_columns].copy()

        df["success"] = df["connection_info.activity_name"].apply(self._is_successful_conn_state)
        df = df.rename(
            columns={
                "connection_info.activity_name": "state",
                "connection_info.history": "history",
            }
        )

        # Deterministic ordering for stable frontends/tests
        df = df.sort_values(
            by=[
                "src_endpoint.ip",
                "dst_endpoint.ip",
                "dst_endpoint.port",
                "success",
                "state",
            ],
            kind="mergesort",
        )

        if len(df) > limit:
            df = df.head(limit)

        return list(df.replace({np.nan: None}).to_dict("records"))

    def _ip_to_endpoint_details(self) -> pd.DataFrame:
        """Build an IP-keyed endpoint lookup with manufacturer and device flags."""
        rows: list[dict[str, object]] = []

        if self.endpoints_df.empty:
            return pd.DataFrame(
                columns=[
                    "ip",
                    "device.mac",
                    "device.manufacturer",
                    "device.is_ot",
                    "device.is_edge",
                    "device.ipv4_subnets",
                    "device.ipv6_subnets",
                ]
            )

        endpoints_reset = self.endpoints_df.reset_index()
        for _, row in endpoints_reset.iterrows():
            endpoint_mac = row.get("device.mac")
            ipv4_ips = row.get("device.ipv4_ips") if isinstance(row.get("device.ipv4_ips"), list) else []
            ipv6_ips = row.get("device.ipv6_ips") if isinstance(row.get("device.ipv6_ips"), list) else []
            for ip in [*ipv4_ips, *ipv6_ips]:
                if not isinstance(ip, str) or not ip:
                    continue
                rows.append(
                    {
                        "ip": ip,
                        "device.mac": endpoint_mac,
                        "device.manufacturer": row.get("device.manufacturer"),
                        "device.is_ot": row.get("device.is_ot"),
                        "device.is_edge": row.get("device.is_edge"),
                        "device.ipv4_subnets": row.get("device.ipv4_subnets"),
                        "device.ipv6_subnets": row.get("device.ipv6_subnets"),
                    }
                )

        if not rows:
            return pd.DataFrame(
                columns=[
                    "ip",
                    "device.mac",
                    "device.manufacturer",
                    "device.is_ot",
                    "device.is_edge",
                    "device.ipv4_subnets",
                    "device.ipv6_subnets",
                ]
            )

        return pd.DataFrame(rows).drop_duplicates(subset=["ip"], keep="first")

    def _connection_detail_base_df(self) -> pd.DataFrame:
        """Return per-connection detail DataFrame for drill‑down endpoints."""
        required_cols = {
            "src_endpoint.ip",
            "src_endpoint.port",
            "dst_endpoint.ip",
            "dst_endpoint.port",
            "service.name",
            "connection_info.protocol_name",
            "connection_info.direction_name",
            "connection_info.activity_name",
        }
        missing = required_cols - set(self.traffic_df.columns)
        if missing:
            raise KeyError(f"traffic_df is missing expected columns: {sorted(missing)}")

        selected_columns = [
            "src_endpoint.ip",
            "src_endpoint.port",
            "dst_endpoint.ip",
            "dst_endpoint.port",
            "service.name",
            "connection_info.protocol_name",
            "connection_info.direction_name",
            "connection_info.activity_name",
        ]
        if "connection_info.history" in self.traffic_df.columns:
            selected_columns.append("connection_info.history")
        if "src_endpoint.subnet" in self.traffic_df.columns:
            selected_columns.append("src_endpoint.subnet")
        if "dst_endpoint.subnet" in self.traffic_df.columns:
            selected_columns.append("dst_endpoint.subnet")

        df = self.traffic_df[selected_columns].copy()
        df["success"] = df["connection_info.activity_name"].apply(self._is_successful_conn_state)
        df = df.rename(
            columns={
                "connection_info.activity_name": "state",
                "connection_info.history": "history",
            }
        )

        endpoint_lookup = self._ip_to_endpoint_details()
        if not endpoint_lookup.empty:
            src_lookup = endpoint_lookup.rename(
                columns={
                    "ip": "src_endpoint.ip",
                    "device.mac": "src_device.mac",
                    "device.manufacturer": "src_device.manufacturer",
                    "device.is_ot": "src_device.is_ot",
                    "device.is_edge": "src_device.is_edge",
                }
            )
            dst_lookup = endpoint_lookup.rename(
                columns={
                    "ip": "dst_endpoint.ip",
                    "device.mac": "dst_device.mac",
                    "device.manufacturer": "dst_device.manufacturer",
                    "device.is_ot": "dst_device.is_ot",
                    "device.is_edge": "dst_device.is_edge",
                }
            )
            df = df.merge(
                src_lookup[
                    [
                        "src_endpoint.ip",
                        "src_device.mac",
                        "src_device.manufacturer",
                        "src_device.is_ot",
                        "src_device.is_edge",
                    ]
                ],
                on="src_endpoint.ip",
                how="left",
            )
            df = df.merge(
                dst_lookup[
                    [
                        "dst_endpoint.ip",
                        "dst_device.mac",
                        "dst_device.manufacturer",
                        "dst_device.is_ot",
                        "dst_device.is_edge",
                    ]
                ],
                on="dst_endpoint.ip",
                how="left",
            )
        return df

    @staticmethod
    def _finalize_connection_detail_df(df: pd.DataFrame, limit: int) -> list[dict[str, object]]:
        """Sort, cap, and serialize connection detail rows."""
        if limit <= 0 or df.empty:
            return []

        df = df.sort_values(
            by=[
                "src_endpoint.ip",
                "dst_endpoint.ip",
                "dst_endpoint.port",
                "src_endpoint.port",
                "state",
            ],
            kind="mergesort",
        )

        if len(df) > limit:
            df = df.head(limit)

        return list(df.replace({np.nan: None}).to_dict("records"))

    def service_connection_lines(self, service_name: str, limit: int = 500) -> list[dict[str, object]]:
        """Return detailed connection rows for a specific service."""
        if limit <= 0 or self.traffic_df.empty:
            return []

        df = self._connection_detail_base_df()
        df = df[df["service.name"] == service_name]
        return self._finalize_connection_detail_df(df, limit)

    def connections_by_state(self, state: str, limit: int = 500) -> list[dict[str, object]]:
        """Return detailed connection rows for a specific Zeek state."""
        if limit <= 0 or self.traffic_df.empty:
            return []

        df = self._connection_detail_base_df()
        df = df[df["state"] == state]
        return self._finalize_connection_detail_df(df, limit)

    def suspicious_outbound_connection_lines(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        service_name: str,
        limit: int = 500,
    ) -> list[dict[str, object]]:
        """Return detailed rows for a suspicious outbound connection grouping."""
        if limit <= 0 or self.traffic_df.empty:
            return []

        df = self._connection_detail_base_df()
        df = df[
            (df["connection_info.direction_name"] == "outbound")
            & (df["src_endpoint.ip"] == src_ip)
            & (df["dst_endpoint.ip"] == dst_ip)
            & (df["dst_endpoint.port"] == dst_port)
            & (df["service.name"] == service_name)
        ]
        return self._finalize_connection_detail_df(df, limit)

    def cross_segment_connections_by_subnet_pair(
        self,
        src_subnet: str,
        dst_subnet: str,
        limit: int = 500,
    ) -> list[dict[str, object]]:
        """Return cross‑segment rows for a source‑dest subnet pair."""
        if limit <= 0 or self.traffic_df.empty:
            return []

        df = self._connection_detail_base_df()
        df = df[
            df["src_endpoint.subnet"].notna()
            & df["dst_endpoint.subnet"].notna()
            & (df["src_endpoint.subnet"] != df["dst_endpoint.subnet"])
            & (df["src_endpoint.subnet"] == src_subnet)
            & (df["dst_endpoint.subnet"] == dst_subnet)
        ]
        return self._finalize_connection_detail_df(df, limit)

    def connection_lines_filtered(
        self,
        *,
        ip: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        subnet: str | None = None,
        src_subnet: str | None = None,
        dst_subnet: str | None = None,
        manufacturer: str | None = None,
        service_name: str | None = None,
        connection_state: str | None = None,
        direction: str | None = None,
        success: bool | None = None,
        is_ot: bool | None = None,
        limit: int = 500,
    ) -> list[dict[str, object]]:
        """Return connection rows matching the provided filter set."""
        if limit <= 0 or self.traffic_df.empty:
            return []

        df = self._connection_detail_base_df()

        if ip:
            df = df[(df["src_endpoint.ip"] == ip) | (df["dst_endpoint.ip"] == ip)]
        if src_ip:
            df = df[df["src_endpoint.ip"] == src_ip]
        if dst_ip:
            df = df[df["dst_endpoint.ip"] == dst_ip]
        if subnet:
            subnet_mask = pd.Series(False, index=df.index)
            if "src_endpoint.subnet" in df.columns:
                subnet_mask = subnet_mask | (df["src_endpoint.subnet"] == subnet)
            if "dst_endpoint.subnet" in df.columns:
                subnet_mask = subnet_mask | (df["dst_endpoint.subnet"] == subnet)
            df = df[subnet_mask]
        if src_subnet and "src_endpoint.subnet" in df.columns:
            df = df[df["src_endpoint.subnet"] == src_subnet]
        if dst_subnet and "dst_endpoint.subnet" in df.columns:
            df = df[df["dst_endpoint.subnet"] == dst_subnet]
        if manufacturer:
            manufacturer_lower = manufacturer.lower()
            src_manufacturer = (
                df["src_device.manufacturer"].fillna("").astype(str).str.lower()
                if "src_device.manufacturer" in df.columns
                else pd.Series("", index=df.index)
            )
            dst_manufacturer = (
                df["dst_device.manufacturer"].fillna("").astype(str).str.lower()
                if "dst_device.manufacturer" in df.columns
                else pd.Series("", index=df.index)
            )
            df = df[(src_manufacturer == manufacturer_lower) | (dst_manufacturer == manufacturer_lower)]
        if service_name:
            df = df[df["service.name"] == service_name]
        if connection_state:
            df = df[df["state"] == connection_state]
        if direction:
            df = df[df["connection_info.direction_name"] == direction]
        if success is not None:
            df = df[df["success"] == success]
        if is_ot is not None:
            src_ot = (
                df["src_device.is_ot"].fillna(False)
                if "src_device.is_ot" in df.columns
                else pd.Series(False, index=df.index)
            )
            dst_ot = (
                df["dst_device.is_ot"].fillna(False)
                if "dst_device.is_ot" in df.columns
                else pd.Series(False, index=df.index)
            )
            df = df[(src_ot == is_ot) | (dst_ot == is_ot)]

        return self._finalize_connection_detail_df(df, limit)

    def devices_filtered(
        self,
        *,
        manufacturer: str | None = None,
        subnet: str | None = None,
        service_name: str | None = None,
        is_ot: bool | None = None,
        is_edge: bool | None = None,
    ) -> list[dict[str, object]]:
        """Return device rows matching the provided filters."""
        if self.endpoints_df.empty:
            return []

        df = self.endpoints_df.reset_index().copy()

        if manufacturer:
            df = df[df["device.manufacturer"].fillna("").astype(str).str.lower() == manufacturer.lower()]

        if subnet:

            def _row_has_subnet(row: pd.Series) -> bool:
                ipv4_subnets = (
                    row.get("device.ipv4_subnets") if isinstance(row.get("device.ipv4_subnets"), list) else []
                )
                ipv6_subnets = (
                    row.get("device.ipv6_subnets") if isinstance(row.get("device.ipv6_subnets"), list) else []
                )
                return subnet in [*ipv4_subnets, *ipv6_subnets]

            df = df[df.apply(_row_has_subnet, axis=1)]

        if service_name:

            def _row_has_service(row: pd.Series) -> bool:
                incoming = (
                    row.get("device.incoming_services") if isinstance(row.get("device.incoming_services"), list) else []
                )
                sent = row.get("device.sent_services") if isinstance(row.get("device.sent_services"), list) else []
                return service_name in [*incoming, *sent]

            df = df[df.apply(_row_has_service, axis=1)]

        if is_ot is not None and "device.is_ot" in df.columns:
            df = df[df["device.is_ot"] == is_ot]
        if is_edge is not None and "device.is_edge" in df.columns:
            df = df[df["device.is_edge"] == is_edge]

        device_columns = {
            "device.mac": "mac",
            "device.manufacturer": "manufacturer",
            "device.ipv4_ips": "ipv4_ips",
            "device.ipv6_ips": "ipv6_ips",
            "device.ipv4_subnets": "ipv4_subnets",
            "device.ipv6_subnets": "ipv6_subnets",
            "device.incoming_services": "incoming_services",
            "device.sent_services": "sent_services",
            "device.is_ot": "is_ot",
            "device.is_edge": "is_edge",
        }

        existing_cols = {k: v for k, v in device_columns.items() if k in df.columns}
        result_df = df[list(existing_cols.keys())].rename(columns=existing_cols)
        return cast(
            list[dict[str, object]],
            result_df.replace({np.nan: None}).to_dict("records"),
        )

    def services_filtered(
        self,
        *,
        subnet: str | None = None,
        manufacturer: str | None = None,
        device_ip: str | None = None,
        risk_category: str | None = None,
        service_name: str | None = None,
    ) -> list[dict[str, object]]:
        """Return service rows matching the provided filters."""
        if self.services_df.empty:
            return []

        df = self.services_df.copy()

        if risk_category:
            df = df[
                df["service.risk_categories"]
                .fillna("")
                .astype(str)
                .apply(lambda value: risk_category in [item.strip() for item in value.split(",")] if value else False)
            ]

        if service_name:
            df = df[df["service.name"] == service_name]

        if subnet or manufacturer or device_ip:
            allowed_connections = self._connection_detail_base_df()
            if subnet:
                subnet_mask = pd.Series(False, index=allowed_connections.index)
                if "src_endpoint.subnet" in allowed_connections.columns:
                    subnet_mask = subnet_mask | (allowed_connections["src_endpoint.subnet"] == subnet)
                if "dst_endpoint.subnet" in allowed_connections.columns:
                    subnet_mask = subnet_mask | (allowed_connections["dst_endpoint.subnet"] == subnet)
                allowed_connections = allowed_connections[subnet_mask]
            if manufacturer:
                manufacturer_lower = manufacturer.lower()
                src_manufacturer = (
                    allowed_connections["src_device.manufacturer"].fillna("").astype(str).str.lower()
                    if "src_device.manufacturer" in allowed_connections.columns
                    else pd.Series("", index=allowed_connections.index)
                )
                dst_manufacturer = (
                    allowed_connections["dst_device.manufacturer"].fillna("").astype(str).str.lower()
                    if "dst_device.manufacturer" in allowed_connections.columns
                    else pd.Series("", index=allowed_connections.index)
                )
                allowed_connections = allowed_connections[
                    (src_manufacturer == manufacturer_lower) | (dst_manufacturer == manufacturer_lower)
                ]
            if device_ip:
                allowed_connections = allowed_connections[
                    (allowed_connections["src_endpoint.ip"] == device_ip)
                    | (allowed_connections["dst_endpoint.ip"] == device_ip)
                ]
            allowed_service_names = set(allowed_connections["service.name"].dropna().unique())
            df = df[df["service.name"].isin(allowed_service_names)]

        return list(df.replace({np.nan: None}).to_dict("records"))
