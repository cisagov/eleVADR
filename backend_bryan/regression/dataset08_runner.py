from __future__ import annotations

from copy import deepcopy
from typing import Callable

from backend_bryan.adapters.detection_context_adapter import compile_detection_context_metadata
from backend_bryan.integration.detector_runtime import ensure_detector_package


def _profile() -> dict:
    return {
        "schemaVersion": 3,
        "id": "regression-08",
        "name": "Regression 08 - Policy Precedence",
        "segments": [],
        "assets": [],
        "infrastructure": [],
        "communicationPairs": [],
        "allowedHosts": [],
        "allowedSegmentPairs": [],
        "approvedExternalDestinations": [],
        "captureScope": {
            "internalIcsOnlyExpected": False,
            "dedicatedOtSensor": True,
            "ipv4OnlyExpected": False,
        },
        "authorizedControlActions": [],
        "modulePolicies": {},
        "scan": {},
    }


def _conn(src: str, dst: str, port: int, service: str, uid: str = "C1") -> dict:
    return {
        "uid": uid,
        "timestamp": 100.0,
        "source_ip": src,
        "destination_ip": dst,
        "destination_port": port,
        "protocol": "tcp",
        "service": service,
        "conn_state": "SF",
        "orig_bytes": 100,
        "resp_bytes": 100,
        "local_resp": False,
    }


def _modbus(src: str, dst: str, code: int = 6) -> dict:
    return {
        "uid": "M1",
        "timestamp": 100.0,
        "source_ip": src,
        "destination_ip": dst,
        "source_port": 40000,
        "destination_port": 502,
        "function_code": code,
        "function_name": "write_single_register" if code == 6 else "write_multiple_registers",
    }


def run_cases(verbose: bool = True) -> list[str]:
    AnalysisContext, modules, _module_file = ensure_detector_package()
    failures: list[str] = []
    passed = 0

    def check(label: str, fn: Callable[[], None]) -> None:
        nonlocal passed
        try:
            fn()
        except Exception as exc:
            failures.append(f"{label}: {type(exc).__name__}: {exc}")
            if verbose:
                print(f"FAIL  {label} ({type(exc).__name__}: {exc})")
        else:
            passed += 1
            if verbose:
                print(f"PASS  {label}")

    if verbose:
        print("\n=== 08_policy_precedence: Conflicting Detection Context policy and identity semantics ===")

    def longest_prefix_ot_wins() -> None:
        p = _profile()
        p["segments"] = [
            {"name": "Broad IT", "cidr": "10.80.0.0/16", "role": "IT", "purdueLevel": "Level 4"},
            {"name": "Control Cell", "cidr": "10.80.10.0/24", "role": "OT", "purdueLevel": "Level 1"},
        ]
        p["assets"] = [{"ip": "10.80.10.5", "role": "IT", "assetType": "Engineering Workstation", "source": "user"}]
        md = compile_detection_context_metadata(p)
        ctx = AnalysisContext(connections=[_conn("10.80.10.5", "8.8.8.8", 443, "ssl")], metadata=md)
        result = modules["ot_outbound_internet_any_protocol"].analyze(ctx)
        assert len(result.findings) == 1
        assert result.findings[0].metadata["classification_source"] == "segment"
    check("Most-specific OT segment overrides broader IT segment and conflicting asset label", longest_prefix_ot_wins)

    def longest_prefix_it_wins() -> None:
        p = _profile()
        p["segments"] = [
            {"name": "Broad OT", "cidr": "10.80.0.0/16", "role": "OT", "purdueLevel": "Level 2"},
            {"name": "Engineering IT", "cidr": "10.80.10.0/24", "role": "IT", "purdueLevel": "Level 4"},
        ]
        p["assets"] = [{"ip": "10.80.10.5", "role": "OT", "assetType": "HMI", "source": "user"}]
        md = compile_detection_context_metadata(p)
        ctx = AnalysisContext(connections=[_conn("10.80.10.5", "8.8.8.8", 443, "ssl")], metadata=md)
        result = modules["ot_outbound_internet_any_protocol"].analyze(ctx)
        assert len(result.findings) == 0
    check("Most-specific IT segment overrides broader OT segment and conflicting OT asset label", longest_prefix_it_wins)

    def explicit_module_identity_wins() -> None:
        p = _profile()
        p["segments"] = [{"name": "IT", "cidr": "10.80.10.0/24", "role": "IT"}]
        p["modulePolicies"] = {"ot_outbound_internet_any_protocol": {"ot_hosts": ["10.80.10.5"]}}
        md = compile_detection_context_metadata(p)
        ctx = AnalysisContext(connections=[_conn("10.80.10.5", "8.8.8.8", 443, "ssl")], metadata=md)
        result = modules["ot_outbound_internet_any_protocol"].analyze(ctx)
        assert len(result.findings) == 1
        assert result.findings[0].metadata["classification_source"] == "policy"
    check("Explicit detector OT-host policy overrides segment identity", explicit_module_identity_wins)

    def observed_pair_never_authorizes_write() -> None:
        p = _profile()
        p["communicationPairs"] = [{
            "sourceIp": "10.10.1.10", "destinationIp": "10.10.2.20",
            "protocol": "modbus", "destinationPort": 502, "source": "zeek", "confidence": "high",
        }]
        md = compile_detection_context_metadata(p)
        assert "ics_write_policy" not in md
        result = modules["ics_write_operations"].analyze(AnalysisContext(modbus=[_modbus("10.10.1.10", "10.10.2.20")], metadata=md))
        assert len(result.findings) == 1
        assert result.findings[0].metadata["policy_status"] == "unprofiled_write"
    check("Observed communication pair does not authorize a Modbus write", observed_pair_never_authorizes_write)

    def exact_control_authorization_suppresses_only_match() -> None:
        p = _profile()
        p["authorizedControlActions"] = [{
            "protocol": "modbus", "source": "10.10.1.10", "destination": "10.10.2.20",
            "allowedFunctionCodes": [6], "allowedOperations": ["write"],
        }]
        md = compile_detection_context_metadata(p)
        allowed = modules["ics_write_operations"].analyze(AnalysisContext(modbus=[_modbus("10.10.1.10", "10.10.2.20", 6)], metadata=md))
        wrong_function = modules["ics_write_operations"].analyze(AnalysisContext(modbus=[_modbus("10.10.1.10", "10.10.2.20", 16)], metadata=md))
        wrong_source = modules["ics_write_operations"].analyze(AnalysisContext(modbus=[_modbus("10.10.1.11", "10.10.2.20", 6)], metadata=md))
        assert len(allowed.findings) == 0
        assert len(wrong_function.findings) == 1
        assert len(wrong_source.findings) == 1
    check("Control authorization is path/function scoped and does not broaden to neighbors", exact_control_authorization_suppresses_only_match)

    def trusted_dns_is_service_scoped() -> None:
        p = _profile()
        p["segments"] = [
            {"name": "OT", "cidr": "10.20.0.0/24", "role": "OT"},
            {"name": "Enterprise", "cidr": "10.30.0.0/24", "role": "IT"},
        ]
        p["infrastructure"] = [{"kind": "dns", "value": "10.30.0.53"}]
        md = compile_detection_context_metadata(p)
        dns = modules["control_system_enterprise_non_dmz"].analyze(
            AnalysisContext(connections=[_conn("10.20.0.10", "10.30.0.53", 53, "dns")], metadata=md)
        )
        ssh = modules["control_system_enterprise_non_dmz"].analyze(
            AnalysisContext(connections=[_conn("10.20.0.10", "10.30.0.53", 22, "ssh")], metadata=md)
        )
        assert len(dns.findings) == 0
        assert len(ssh.findings) == 1
    check("Trusted infrastructure exception is service scoped, not a host-wide bypass", trusted_dns_is_service_scoped)

    def allowed_segment_pair_is_detector_scoped() -> None:
        p = _profile()
        p["segments"] = [
            {"name": "OT", "cidr": "10.20.0.0/24", "role": "OT"},
            {"name": "Enterprise", "cidr": "10.30.0.0/24", "role": "IT"},
        ]
        p["allowedSegmentPairs"] = [{"sourceSegment": "OT", "destinationSegment": "Enterprise"}]
        md = compile_detection_context_metadata(p)
        assert md["control_system_enterprise_policy"]["allowed_segment_pairs"]
        assert "allowed_segment_pairs" not in md.get("ot_outbound_internet_policy", {})
        architecture = modules["control_system_enterprise_non_dmz"].analyze(
            AnalysisContext(connections=[_conn("10.20.0.10", "10.30.0.20", 22, "ssh")], metadata=md)
        )
        assert len(architecture.findings) == 0
    check("Allowed segment pair affects only mapped detector scopes", allowed_segment_pair_is_detector_scoped)

    def external_allowlist_is_destination_scoped() -> None:
        p = _profile()
        p["segments"] = [{"name": "OT", "cidr": "10.20.0.0/24", "role": "OT"}]
        p["approvedExternalDestinations"] = ["8.8.8.0/24"]
        md = compile_detection_context_metadata(p)
        approved = modules["ot_outbound_internet_any_protocol"].analyze(
            AnalysisContext(connections=[_conn("10.20.0.10", "8.8.8.8", 443, "ssl")], metadata=md)
        )
        other = modules["ot_outbound_internet_any_protocol"].analyze(
            AnalysisContext(connections=[_conn("10.20.0.10", "1.1.1.1", 443, "ssl")], metadata=md)
        )
        assert len(approved.findings) == 0
        assert len(other.findings) == 1
        assert "ics_write_policy" not in md
    check("Approved external destination suppresses only matching egress and creates no control authorization", external_allowlist_is_destination_scoped)

    def generic_allowed_host_not_egress_allowlist() -> None:
        p = _profile()
        p["segments"] = [{"name": "OT", "cidr": "10.20.0.0/24", "role": "OT"}]
        p["allowedHosts"] = ["8.8.8.8"]
        md = compile_detection_context_metadata(p)
        result = modules["ot_outbound_internet_any_protocol"].analyze(
            AnalysisContext(connections=[_conn("10.20.0.10", "8.8.8.8", 443, "ssl")], metadata=md)
        )
        assert len(result.findings) == 1
    check("Generic allowed-host exception does not become an outbound Internet allowlist", generic_allowed_host_not_egress_allowlist)

    def advanced_override_wins_over_first_class() -> None:
        p = _profile()
        p["captureScope"]["internalIcsOnlyExpected"] = True
        p["modulePolicies"] = {"public_to_public_traffic": {"internal_ics_only_expected": False, "min_flows": 7}}
        md = compile_detection_context_metadata(p)
        policy = md["public_to_public_policy"]
        assert policy["internal_ics_only_expected"] is False
        assert policy["min_flows"] == 7
    check("Advanced module override overlays first-class compiled policy", advanced_override_wins_over_first_class)

    def advanced_egress_override_is_authoritative() -> None:
        p = _profile()
        p["segments"] = [{"name": "OT", "cidr": "10.20.0.0/24", "role": "OT"}]
        p["approvedExternalDestinations"] = ["8.8.8.8"]
        p["modulePolicies"] = {"ot_outbound_internet_any_protocol": {"allowed_external_destinations": ["1.1.1.1"]}}
        md = compile_detection_context_metadata(p)
        policy = md["ot_outbound_internet_policy"]
        assert policy["allowed_external_destinations"] == ["1.1.1.1"]
        old_profile_allow = modules["ot_outbound_internet_any_protocol"].analyze(
            AnalysisContext(connections=[_conn("10.20.0.10", "8.8.8.8", 443, "ssl")], metadata=md)
        )
        override_allow = modules["ot_outbound_internet_any_protocol"].analyze(
            AnalysisContext(connections=[_conn("10.20.0.10", "1.1.1.1", 443, "ssl")], metadata=md)
        )
        assert len(old_profile_allow.findings) == 1
        assert len(override_allow.findings) == 0
    check("Advanced egress override replaces conflicting first-class destination list for that detector", advanced_egress_override_is_authoritative)

    def zeek_asset_never_becomes_identity_policy() -> None:
        p = _profile()
        p["assets"] = [{"ip": "10.99.0.99", "role": "OT", "assetType": "PLC", "source": "zeek", "confidence": "high"}]
        md = compile_detection_context_metadata(p)
        assert not md["asset_inventory"]
        assert md["detection_context_observations"]["assets"]
        result = modules["ot_outbound_internet_any_protocol"].analyze(
            AnalysisContext(connections=[_conn("10.99.0.99", "8.8.8.8", 443, "ssl")], metadata=md)
        )
        assert len(result.findings) == 0
    check("Zeek-observed OT-looking asset remains observation, not authoritative identity policy", zeek_asset_never_becomes_identity_policy)

    if verbose:
        if failures:
            print(f"FAIL: {len(failures)} Dataset 08 case(s) failed.")
        else:
            print(f"PASS: Dataset 08 verified {passed} policy-precedence/conflict cases.")
    return failures


def main() -> int:
    failures = run_cases(verbose=True)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
