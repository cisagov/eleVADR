"""Registry-wide finding severity/confidence calibration.

Detectors retain ownership of *whether* a finding exists and of their local
threshold semantics.  This layer only normalizes prioritization after a module
fires so comparable evidence is ranked consistently across the 75-module
registry.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

CALIBRATION_VERSION = "1.0"

_SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True, slots=True)
class CalibrationProfile:
    family: str
    behavioral: bool = False
    baseline_drift: bool = False
    policy_sensitive: bool = False
    control_action: bool = False


# Every registry module must be explicitly classified.  Tests fail closed if a
# module is added without a calibration profile.
_FAMILY_MODULES: dict[str, tuple[str, ...]] = {
    "control_policy": (
        "control_system_enterprise_non_dmz", "cross_purdue_level_traffic",
        "enip_cip_write_session_abuses", "ics_write_operations",
        "ot_outbound_internet_any_protocol", "quic_ot_segments",
        "s7comm_unauthorized_write_stop", "snmp_write_ot_devices",
    ),
    "critical_control_action": (
        "plc_program_logic_firmware_update",
    ),
    "infrastructure_policy": (
        "dns_source_drift", "ntp_source_drift", "ot_external_dns_resolver",
        "rogue_dhcp_static_ot", "unexpected_dhcp_server",
        "unexpected_multicast_behavior",
    ),
    "direct_exposure": (
        "cleartext_credentials", "codesys_runtime_exposure",
        "database_service_exposed", "deprecated_insecure_services_protocols",
        "deprecated_vpn_protocol", "engineering_tools_cleartext",
        "iccp_tase2_detected", "internet_exposed_ics", "irc_traffic_detected",
        "ldap_cleartext_anonymous_cross_segment", "netbios_smbv1_exposure",
        "niagara_fox_detected", "ot_management_certificate_risk",
        "ot_protocol_exposure", "protocol_unexpected_high_risk_port",
        "rdp_nla_disabled", "remote_access_tool_exposure",
        "smb_admin_share_access", "smb_signing_disabled_ntlmv1",
        "socks_open_proxy_behavior", "upnp_ssdp_igd_port_mapping",
        "weak_broken_tls_ssl",
    ),
    "attack_behavior": (
        "arp_l2_reconnaissance", "beaconing_c2_communication",
        "brute_force_authentication", "dns_tunneling_exfiltration",
        "high_fan_in_out", "icmp_data_channel", "port_host_scanning",
        "tcp_reset_abort_surge",
    ),
    "data_movement": (
        "file_extraction_sensitive_types", "large_outbound_http_uploads",
        "unusual_outbound_data_volume",
    ),
    "identity_integrity": (
        "arp_ip_mac_identity_change", "unknown_rogue_devices",
        "vlan_tag_mismatch_double_tag",
    ),
    "protocol_anomaly": (
        "bacnet_discovery_anomalies", "http_user_agent_anomalies",
        "ics_protocol_error_spike", "ipv6_traffic_ot",
        "ja3_fingerprint_outliers", "kerberos_asrep_roastable_accounts",
        "llmnr_nbtns_mdns_poisoning_signals", "ntp_internet_multi_dest_ot",
        "public_to_public_traffic", "tls_certificate_anomalies",
        "tls_sni_certificate_reuse", "weird_protocol_violations",
    ),
    "behavioral_drift": (
        "controller_communication_jitter", "encrypted_session_fingerprint_change",
        "engineering_workstation_control_burst", "new_ot_conversation_pair",
        "new_service_emergence_ot", "ot_asset_gone_silent",
        "ot_protocol_role_reversal", "plc_rtu_peer_change",
        "polling_cadence_disruption", "remote_access_session_anomaly",
        "service_disappearance_replacement",
    ),
    "network_condition": (
        "excessive_broadcast_multicast_ot",
    ),
}


def _profile_for_family(family: str) -> CalibrationProfile:
    return CalibrationProfile(
        family=family,
        behavioral=family in {"attack_behavior", "behavioral_drift", "network_condition"},
        baseline_drift=family == "behavioral_drift",
        policy_sensitive=family in {"control_policy", "infrastructure_policy"},
        control_action=family in {"control_policy", "critical_control_action"},
    )


CALIBRATION_PROFILES: dict[str, CalibrationProfile] = {
    module_id: _profile_for_family(family)
    for family, module_ids in _FAMILY_MODULES.items()
    for module_id in module_ids
}


def _clamp(value: str, order: dict[str, int], *, minimum: str | None = None, maximum: str | None = None) -> str:
    rank = order[value]
    if minimum is not None:
        rank = max(rank, order[minimum])
    if maximum is not None:
        rank = min(rank, order[maximum])
    reverse = {rank_value: name for name, rank_value in order.items()}
    return reverse[rank]


def _explicit_policy_violation(finding: Any) -> bool:
    text = " ".join(
        str(value).lower()
        for value in (
            getattr(finding, "title", ""),
            getattr(finding, "summary", ""),
            " ".join(str(tag) for tag in (getattr(finding, "tags", None) or [])),
        )
    )
    markers = (
        "unauthorized", "unapproved", "not authorized", "outside allowed",
        "policy violation", "policy-violation", "forbidden", "disallowed",
        "unexpected dhcp server", "outside trusted infrastructure",
    )
    return any(marker in text for marker in markers)


def calibrate_finding(module_id: str, finding: Any) -> Any:
    """Normalize one finding in place and attach an auditable calibration record."""
    profile = CALIBRATION_PROFILES.get(module_id)
    if profile is None:
        raise KeyError(f"No finding calibration profile registered for module '{module_id}'")

    original_severity = str(getattr(finding, "severity", "medium")).lower()
    original_confidence = str(getattr(finding, "confidence", "medium")).lower()
    basis = str(getattr(finding, "detection_basis", "derived")).lower()
    severity = original_severity
    confidence = original_confidence
    reasons: list[str] = []

    # Evidence-strength calibration.  Port-only/heuristic observations cannot
    # claim high confidence; native protocol/service evidence should not be low.
    if basis in {"port", "heuristic"}:
        adjusted = _clamp(confidence, _CONFIDENCE_ORDER, maximum="medium")
        if adjusted != confidence:
            reasons.append(f"{basis} evidence caps confidence at medium")
            confidence = adjusted
    elif basis in {"protocol_log", "zeek_service"}:
        adjusted = _clamp(confidence, _CONFIDENCE_ORDER, minimum="medium")
        if adjusted != confidence:
            reasons.append(f"{basis} evidence floors confidence at medium")
            confidence = adjusted

    # Baseline/behavioral drift is valuable triage evidence but is inherently
    # contextual.  Derived drift stays Medium/Medium unless the detector itself
    # has direct protocol evidence or an explicit policy breach is present.
    explicit_violation = profile.policy_sensitive and _explicit_policy_violation(finding)
    if profile.baseline_drift and basis in {"derived", "heuristic"} and not explicit_violation:
        new_severity = _clamp(severity, _SEVERITY_ORDER, maximum="medium")
        new_confidence = _clamp(confidence, _CONFIDENCE_ORDER, maximum="medium")
        if new_severity != severity:
            reasons.append("derived baseline drift caps severity at medium")
            severity = new_severity
        if new_confidence != confidence:
            reasons.append("derived baseline drift caps confidence at medium")
            confidence = new_confidence

    # Explicitly identified policy/control violations outrank generic anomalies.
    # Critical remains reserved for detectors that already make that stronger
    # assertion; calibration never invents Critical severity.
    if explicit_violation:
        new_severity = _clamp(severity, _SEVERITY_ORDER, minimum="high")
        if new_severity != severity:
            reasons.append("explicit policy/control violation floors severity at high")
            severity = new_severity
        if basis in {"protocol_log", "zeek_service"}:
            new_confidence = _clamp(confidence, _CONFIDENCE_ORDER, minimum="high")
            if new_confidence != confidence:
                reasons.append("direct evidence of explicit policy violation floors confidence at high")
                confidence = new_confidence

    # Direct control actions are never triaged below Medium when the detector
    # has enough evidence to emit a finding, even if no explicit allow/deny
    # policy was configured.
    if profile.control_action and basis in {"protocol_log", "zeek_service"}:
        new_severity = _clamp(severity, _SEVERITY_ORDER, minimum="medium")
        if new_severity != severity:
            reasons.append("direct control-action evidence floors severity at medium")
            severity = new_severity

    setattr(finding, "severity", severity)
    setattr(finding, "confidence", confidence)

    metadata = getattr(finding, "metadata", None)
    if not isinstance(metadata, dict):
        metadata = {}
        setattr(finding, "metadata", metadata)
    metadata["confidence"] = confidence
    metadata["detection_basis"] = basis
    metadata["calibration"] = {
        "version": CALIBRATION_VERSION,
        "family": profile.family,
        "original_severity": original_severity,
        "severity": severity,
        "original_confidence": original_confidence,
        "confidence": confidence,
        "explicit_policy_violation": explicit_violation,
        "adjusted": severity != original_severity or confidence != original_confidence,
        "reasons": reasons,
    }
    return finding


def calibrate_module_result(module: Any, result: Any) -> Any:
    findings = getattr(result, "findings", None)
    if findings is None and isinstance(result, dict):
        findings = result.get("findings", [])
    # Some integration/failure-isolation tests and third-party adapters expose
    # only a serialized result. There is no mutable Finding object to calibrate.
    if not findings:
        return result

    module_id = str(getattr(getattr(module, "metadata", None), "id", ""))
    if not module_id or module_id not in CALIBRATION_PROFILES:
        # The built-in registry is exhaustively covered (enforced by tests), but
        # do not make an extension module fail merely because it has no eleVADR
        # calibration profile yet. Preserve its labels and mark it unclassified.
        for finding in findings:
            metadata = getattr(finding, "metadata", None)
            if isinstance(metadata, dict):
                metadata.setdefault("calibration", {
                    "version": CALIBRATION_VERSION,
                    "family": "unclassified",
                    "adjusted": False,
                    "reasons": ["module is outside the built-in calibrated registry"],
                })
        return result

    for finding in findings:
        calibrate_finding(module_id, finding)
    return result
