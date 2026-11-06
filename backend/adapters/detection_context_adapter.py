"""Detection Context v3 -> AnalysisContext.metadata reference adapter.

This module is intentionally isolated from the production backend. It accepts the
JSON shape exported by the frontend Detection Context editor and produces the
metadata dictionary consumed by the standalone ``elevadr_modules`` detector
package.

Observed Zeek facts and site policy are kept separate. In particular, observed
communications are never promoted to allowed pairs or control-write authorization.
"""
from __future__ import annotations

import ipaddress

from pathlib import Path
from typing import Any, Mapping
import json

Metadata = dict[str, Any]
Profile = Mapping[str, Any]

MODULE_POLICY_NAMESPACE: dict[str, str] = {
    "arp_ip_mac_identity_change": "arp_identity_policy",
    "unexpected_dhcp_server": "unexpected_dhcp_server_policy",
    "ot_protocol_role_reversal": "ot_role_reversal_policy",
    "plc_rtu_peer_change": "plc_rtu_peer_change_policy",
    "engineering_workstation_control_burst": "engineering_control_burst_policy",
    "dns_source_drift": "dns_source_drift_policy",
    "ntp_source_drift": "ntp_source_drift_policy",
    "arp_l2_reconnaissance": "arp_reconnaissance_policy",
    "unexpected_multicast_behavior": "unexpected_multicast_policy",
    "tcp_reset_abort_surge": "tcp_reset_abort_policy",
    "encrypted_session_fingerprint_change": "encrypted_session_fingerprint_policy",
    "remote_access_session_anomaly": "remote_access_session_anomaly_policy",
    "service_disappearance_replacement": "service_disappearance_replacement_policy",
    "polling_cadence_disruption": "polling_cadence_disruption_policy",
    "controller_communication_jitter": "controller_communication_jitter_policy",
    "bacnet_discovery_anomalies": "bacnet_discovery_policy",
    "codesys_runtime_exposure": "codesys_runtime_policy",
    "control_system_enterprise_non_dmz": "control_system_enterprise_policy",
    "cross_purdue_level_traffic": "purdue_policy",
    "database_service_exposed": "database_exposure_policy",
    "deprecated_vpn_protocol": "deprecated_vpn_policy",
    "engineering_tools_cleartext": "engineering_cleartext_policy",
    "enip_cip_write_session_abuses": "enip_cip_policy",
    "excessive_broadcast_multicast_ot": "broadcast_multicast_ot_policy",
    "file_extraction_sensitive_types": "file_transfer_policy",
    "high_fan_in_out": "fan_in_out_policy",
    "http_user_agent_anomalies": "http_user_agent_policy",
    "iccp_tase2_detected": "iccp_tase2_policy",
    "icmp_data_channel": "icmp_data_channel_policy",
    "ics_protocol_error_spike": "ics_protocol_error_policy",
    "ics_write_operations": "ics_write_policy",
    "internet_exposed_ics": "internet_exposed_ics_policy",
    "ipv6_traffic_ot": "ipv6_ot_policy",
    "irc_traffic_detected": "irc_traffic_policy",
    "ja3_fingerprint_outliers": "ja3_outlier_policy",
    "large_outbound_http_uploads": "http_upload_policy",
    "llmnr_nbtns_mdns_poisoning_signals": "name_resolution_poisoning_policy",
    "netbios_smbv1_exposure": "netbios_smbv1_policy",
    "new_ot_conversation_pair": "ot_comm_matrix_policy",
    "new_service_emergence_ot": "service_baseline_policy",
    "niagara_fox_detected": "niagara_fox_policy",
    "ntp_internet_multi_dest_ot": "ntp_ot_policy",
    "ot_asset_gone_silent": "ot_asset_silence_policy",
    "ot_external_dns_resolver": "ot_dns_policy",
    "ot_management_certificate_risk": "ot_certificate_policy",
    "ot_outbound_internet_any_protocol": "ot_outbound_internet_policy",
    "plc_program_logic_firmware_update": "plc_program_firmware_policy",
    "public_to_public_traffic": "public_to_public_policy",
    "quic_ot_segments": "quic_ot_policy",
    "remote_access_tool_exposure": "remote_access_tool_policy",
    "rogue_dhcp_static_ot": "dhcp_ot_policy",
    "s7comm_unauthorized_write_stop": "s7comm_control_policy",
    "snmp_write_ot_devices": "snmp_write_policy",
    "socks_open_proxy_behavior": "proxy_behavior_policy",
    "unusual_outbound_data_volume": "outbound_volume_policy",
    "vlan_tag_mismatch_double_tag": "vlan_policy",
}

HOST_ALLOW_MODULES = (
    "codesys_runtime_exposure",
    "database_service_exposed",
    "deprecated_vpn_protocol",
    "iccp_tase2_detected",
    "ics_protocol_error_spike",
    "irc_traffic_detected",
    "netbios_smbv1_exposure",
    "niagara_fox_detected",
    "remote_access_tool_exposure",
)
HOST_IGNORE_MODULES = (
    "new_ot_conversation_pair",
    "new_service_emergence_ot",
    "ot_asset_gone_silent",
)
SEGMENT_PAIR_MODULES = (
    "control_system_enterprise_non_dmz",
    "database_service_exposed",
    "netbios_smbv1_exposure",
)


def _record_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            text = item.strip()
            if text not in result:
                result.append(text)
    return result


def _policy_merge(metadata: Metadata, key: str, patch: Mapping[str, Any]) -> None:
    current = metadata.get(key)
    base = dict(current) if isinstance(current, Mapping) else {}
    base.update(dict(patch))
    metadata[key] = base


def _control_path(action: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "source": str(action.get("source", "")),
        "destination": str(action.get("destination", "")),
    }
    operations = action.get("allowedOperations")
    codes = action.get("allowedFunctionCodes")
    if isinstance(operations, list) and operations:
        result["allowed_operations"] = list(operations)
    if isinstance(codes, list) and codes:
        result["allowed_function_codes"] = list(codes)
    return result


def validate_profile_v3(profile: Profile) -> None:
    """Validate only the adapter boundary, not the full frontend UI schema."""
    if not isinstance(profile, Mapping):
        raise TypeError("Detection Context profile must be a JSON object")
    if profile.get("schemaVersion") != 3:
        raise ValueError(
            f"Detection Context adapter requires schemaVersion 3; got {profile.get('schemaVersion')!r}"
        )
    for key in (
        "segments",
        "assets",
        "infrastructure",
        "communicationPairs",
        "allowedHosts",
        "allowedSegmentPairs",
        "approvedExternalDestinations",
        "authorizedControlActions",
    ):
        if key in profile and not isinstance(profile[key], list):
            raise TypeError(f"profile.{key} must be an array")
    if "modulePolicies" in profile and not isinstance(profile["modulePolicies"], Mapping):
        raise TypeError("profile.modulePolicies must be an object")

    for index, segment in enumerate(profile.get("segments", [])):
        if not isinstance(segment, Mapping):
            raise TypeError(f"profile.segments[{index}] must be an object")
        cidr = str(segment.get("cidr", "")).strip()
        if cidr:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ValueError(f"profile.segments[{index}].cidr is invalid: {cidr}") from exc

    for index, asset in enumerate(profile.get("assets", [])):
        if not isinstance(asset, Mapping):
            raise TypeError(f"profile.assets[{index}] must be an object")
        ip = str(asset.get("ip", "")).strip()
        if ip:
            try:
                ipaddress.ip_address(ip)
            except ValueError as exc:
                raise ValueError(f"profile.assets[{index}].ip is invalid: {ip}") from exc

    for index, pair in enumerate(profile.get("communicationPairs", [])):
        if not isinstance(pair, Mapping):
            raise TypeError(f"profile.communicationPairs[{index}] must be an object")
        for field in ("sourceIp", "destinationIp"):
            ip = str(pair.get(field, "")).strip()
            if ip:
                try:
                    ipaddress.ip_address(ip)
                except ValueError as exc:
                    raise ValueError(f"profile.communicationPairs[{index}].{field} is invalid: {ip}") from exc
        port = pair.get("destinationPort")
        if port not in (None, ""):
            try:
                port_value = int(port)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"profile.communicationPairs[{index}].destinationPort must be an integer") from exc
            if not 0 <= port_value <= 65535:
                raise ValueError(f"profile.communicationPairs[{index}].destinationPort must be between 0 and 65535")


def compile_detection_context_metadata(profile: Profile) -> Metadata:
    """Compile a frontend Detection Context v3 profile to detector metadata.

    Deliberate policy rule: scanner-observed communication remains under
    ``detection_context_observations``. Only explicit policy fields create detector
    allowlists or control-action authorization.
    """
    validate_profile_v3(profile)

    segments = _record_list(profile.get("segments", []))
    assets = _record_list(profile.get("assets", []))
    infrastructure = _record_list(profile.get("infrastructure", []))
    communications = _record_list(profile.get("communicationPairs", []))
    segment_pairs = _record_list(profile.get("allowedSegmentPairs", []))
    control_actions = _record_list(profile.get("authorizedControlActions", []))
    capture_scope = profile.get("captureScope") if isinstance(profile.get("captureScope"), Mapping) else {}
    scan = profile.get("scan") if isinstance(profile.get("scan"), Mapping) else {}

    compiled_segments: list[dict[str, Any]] = []
    observed_segments: list[dict[str, Any]] = []
    for segment in segments:
        item: dict[str, Any] = {
            "name": segment.get("name", ""),
            "cidr": segment.get("cidr", ""),
            "role": segment.get("role", "unknown"),
            "addressing": segment.get("addressing", "unknown"),
        }
        if segment.get("purdueLevel") not in (None, ""):
            item["purdue_level"] = segment.get("purdueLevel")
        if segment.get("vlanId") is not None:
            item["vlan_id"] = segment.get("vlanId")
        if segment.get("dhcpAllowed") is not None:
            item["dhcp_allowed"] = segment.get("dhcpAllowed")
        if segment.get("ipv6Allowed") is not None:
            item["ipv6_allowed"] = segment.get("ipv6Allowed")
            item["ipv4_only"] = segment.get("ipv6Allowed") is False
        compiled_segments.append(item)

        observed: dict[str, Any] = {"id": segment.get("id", "")}
        if segment.get("observedDhcp") is not None:
            observed["dhcp_observed"] = segment.get("observedDhcp")
        if isinstance(segment.get("observedOtProtocols"), list) and segment["observedOtProtocols"]:
            observed["ot_protocols_observed"] = list(segment["observedOtProtocols"])
        if isinstance(segment.get("observedVlanIds"), list) and segment["observedVlanIds"]:
            observed["vlan_ids_observed"] = list(segment["observedVlanIds"])
        observed_segments.append(observed)

    compiled_assets: list[dict[str, Any]] = []
    observed_assets: list[dict[str, Any]] = []
    for asset in assets:
        ip = str(asset.get("ip", ""))
        source = str(asset.get("source", "")).strip().lower()
        macs = asset.get("macAddresses") if isinstance(asset.get("macAddresses"), list) else []
        item: dict[str, Any] = {
            "ip": ip,
            "ips": [ip] if ip else [],
            "mac_addresses": list(macs),
            "macs": list(macs),
            "asset_type": asset.get("assetType", ""),
            "role": asset.get("role", ""),
            "services": list(asset.get("services", [])) if isinstance(asset.get("services"), list) else [],
            "ports": list(asset.get("ports", [])) if isinstance(asset.get("ports"), list) else [],
        }
        if asset.get("hostname"):
            item["hostname"] = asset["hostname"]
            item["name"] = asset["hostname"]
        if asset.get("segment"):
            item["segment"] = asset["segment"]
        if asset.get("purdueLevel"):
            item["purdue_level"] = asset["purdueLevel"]

        # Scanner-owned asset rows are observations, not authoritative inventory.
        # Keeping them out of asset_inventory preserves the semantic difference
        # between "seen on the wire" and "known/approved asset" so modules such
        # as unknown_rogue_devices can still detect an intentionally unlisted host.
        if source == "zeek":
            observed = dict(item)
            observed["source_kind"] = "zeek"
            observed["confidence"] = asset.get("confidence", "")
            if asset.get("observedCount") is not None:
                observed["observed_count"] = asset.get("observedCount")
            observed_assets.append(observed)
        else:
            compiled_assets.append(item)

    observed_communications: list[dict[str, Any]] = []
    for pair in communications:
        item: dict[str, Any] = {
            "source": pair.get("sourceIp", ""),
            "destination": pair.get("destinationIp", ""),
            "source_kind": pair.get("source", ""),
            "confidence": pair.get("confidence", ""),
        }
        if pair.get("protocol"):
            item["protocol"] = pair["protocol"]
        if pair.get("destinationPort") is not None:
            item["destination_port"] = pair["destinationPort"]
        if pair.get("service"):
            item["service"] = pair["service"]
        if pair.get("description"):
            item["description"] = pair["description"]
        observed_communications.append(item)

    metadata: Metadata = {
        "detection_context_schema_version": profile.get("schemaVersion"),
        "detection_context_profile_id": profile.get("id", ""),
        "detection_context_profile_name": profile.get("name", ""),
        "segments_source": "detection_context_profile",
        "asset_inventory_source": "detection_context_profile",
        "segments": compiled_segments,
        "asset_inventory": compiled_assets,
        "detection_context_observations": {
            "scan": dict(scan),
            "communications": observed_communications,
            "segments": observed_segments,
            "assets": observed_assets,
        },
    }

    # Capture-scope policy mappings.
    _policy_merge(
        metadata,
        "public_to_public_policy",
        {"internal_ics_only_expected": bool(capture_scope.get("internalIcsOnlyExpected", False))},
    )
    segment_ipv4_only = any(
        segment.get("role") == "ot" and segment.get("ipv6Allowed") is False for segment in segments
    )
    _policy_merge(
        metadata,
        "ipv6_ot_policy",
        {
            "ipv4_only_expected": bool(capture_scope.get("ipv4OnlyExpected", False)) or segment_ipv4_only,
            "scope_all_connections": bool(capture_scope.get("ipv4OnlyExpected", False)),
        },
    )

    # Trusted infrastructure maps only to semantically corresponding policy blocks.
    dns = _dedupe_strings(entry.get("value") for entry in infrastructure if entry.get("kind") == "dns")
    ntp = _dedupe_strings(entry.get("value") for entry in infrastructure if entry.get("kind") == "ntp")
    dhcp = _dedupe_strings(entry.get("value") for entry in infrastructure if entry.get("kind") == "dhcp")
    management = _dedupe_strings(entry.get("value") for entry in infrastructure if entry.get("kind") == "management")
    if dns:
        _policy_merge(metadata, "ot_dns_policy", {"trusted_resolvers": dns})
        _policy_merge(metadata, "dns_source_drift_policy", {"trusted_resolvers": dns})
    if ntp:
        _policy_merge(metadata, "ntp_ot_policy", {"trusted_servers": ntp})
        _policy_merge(metadata, "ntp_source_drift_policy", {"trusted_servers": ntp})

    # Trusted infrastructure is also a service-scoped architecture exception for
    # the direct OT-to-enterprise detector.  The host is suppressed only for its
    # declared infrastructure service/port; this is deliberately narrower than
    # a generic allowed host/pair.
    trusted_service_hosts: list[dict[str, Any]] = []
    trusted_service_hosts.extend({"host": host, "services": ["dns"], "ports": [53]} for host in dns)
    trusted_service_hosts.extend({"host": host, "services": ["ntp"], "ports": [123]} for host in ntp)
    trusted_service_hosts.extend({"host": host, "services": ["dhcp"], "ports": [67, 68]} for host in dhcp)
    if trusted_service_hosts:
        _policy_merge(
            metadata,
            "control_system_enterprise_policy",
            {"trusted_service_hosts": trusted_service_hosts},
        )
    static_segments = _dedupe_strings(
        value
        for segment in segments
        if segment.get("addressing") == "static" or segment.get("dhcpAllowed") is False
        for value in (segment.get("name"), segment.get("cidr"))
    )
    if dhcp or static_segments:
        _policy_merge(metadata, "dhcp_ot_policy", {"expected_servers": dhcp, "static_segments": static_segments})
    if dhcp:
        _policy_merge(metadata, "unexpected_dhcp_server_policy", {"expected_servers": dhcp})
    if management:
        _policy_merge(metadata, "ot_certificate_policy", {"management_hosts": management})
        _policy_merge(metadata, "remote_access_session_anomaly_policy", {"authorized_sources": management})

    # Explicit policy lists. Observed communications are intentionally excluded here.
    allowed_hosts = _string_list(profile.get("allowedHosts", []))
    if allowed_hosts:
        for module_id in HOST_ALLOW_MODULES:
            _policy_merge(metadata, MODULE_POLICY_NAMESPACE[module_id], {"allowed_hosts": allowed_hosts})
        for module_id in HOST_IGNORE_MODULES:
            _policy_merge(metadata, MODULE_POLICY_NAMESPACE[module_id], {"ignored_hosts": allowed_hosts})

    allowed_segment_pairs = [
        {"source": pair.get("sourceSegment", ""), "destination": pair.get("destinationSegment", "")}
        for pair in segment_pairs
    ]
    if allowed_segment_pairs:
        for module_id in SEGMENT_PAIR_MODULES:
            _policy_merge(
                metadata,
                MODULE_POLICY_NAMESPACE[module_id],
                {"allowed_segment_pairs": allowed_segment_pairs},
            )

    external = _string_list(profile.get("approvedExternalDestinations", []))
    if external:
        _policy_merge(metadata, "ot_outbound_internet_policy", {"allowed_external_destinations": external})
        _policy_merge(metadata, "internet_exposed_ics_policy", {"allowed_external_destinations": external})
        _policy_merge(metadata, "file_transfer_policy", {"approved_external_destinations": external})

    # High-risk control authorization comes only from Authorized Control Actions.
    modbus_dnp3 = [a for a in control_actions if a.get("protocol") in {"modbus", "dnp3"}]
    if modbus_dnp3:
        _policy_merge(
            metadata,
            "ics_write_policy",
            {
                "allowed_paths": [
                    {"protocol": action.get("protocol"), **_control_path(action)}
                    for action in modbus_dnp3
                ]
            },
        )

    s7 = [a for a in control_actions if a.get("protocol") == "s7comm"]
    if s7:
        _policy_merge(metadata, "s7comm_control_policy", {"allowed_paths": [_control_path(a) for a in s7]})

    enip = [a for a in control_actions if a.get("protocol") == "enip"]
    if enip:
        paths: list[dict[str, Any]] = []
        for action in enip:
            path: dict[str, Any] = {
                "source": action.get("source", ""),
                "destination": action.get("destination", ""),
            }
            if isinstance(action.get("allowedFunctionCodes"), list) and action["allowedFunctionCodes"]:
                path["allowed_service_codes"] = list(action["allowedFunctionCodes"])
            paths.append(path)
        _policy_merge(metadata, "enip_cip_policy", {"allowed_write_paths": paths})

    if control_actions:
        _policy_merge(
            metadata,
            "engineering_control_burst_policy",
            {
                "authorized_paths": [
                    {"protocol": action.get("protocol"), **_control_path(action)}
                    for action in control_actions
                ]
            },
        )

    if control_actions:
        allowed_pairs: list[dict[str, Any]] = []
        for action in control_actions:
            pair: dict[str, Any] = {
                "source": action.get("source", ""),
                "destination": action.get("destination", ""),
                "protocols": [action.get("protocol")],
            }
            if isinstance(action.get("allowedOperations"), list) and action["allowedOperations"]:
                pair["operations"] = list(action["allowedOperations"])
            allowed_pairs.append(pair)
        _policy_merge(metadata, "plc_program_firmware_policy", {"allowed_pairs": allowed_pairs})

    # Advanced overrides are explicit user policy and overlay first-class compiled values.
    module_policies = profile.get("modulePolicies") if isinstance(profile.get("modulePolicies"), Mapping) else {}
    for module_id, raw_override in module_policies.items():
        if not isinstance(raw_override, Mapping):
            continue
        namespace = MODULE_POLICY_NAMESPACE.get(str(module_id))
        if namespace:
            _policy_merge(metadata, namespace, raw_override)

    return metadata


def compile_profile_file(path: str | Path) -> Metadata:
    """Load a frontend-exported profile JSON file and compile its metadata."""
    profile_path = Path(path)
    with profile_path.open("r", encoding="utf-8") as handle:
        profile = json.load(handle)
    return compile_detection_context_metadata(profile)


def _dedupe_strings(values: Any) -> list[str]:
    result: list[str] = []
    for value in values:
        if isinstance(value, str) and value.strip():
            text = value.strip()
            if text not in result:
                result.append(text)
    return result
