from __future__ import annotations

from collections import Counter, defaultdict
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


_MAX_EVIDENCE = 10
_DEFAULT_POLICY = {
    "minimum_segment_observations": 30,
    "minimum_baseline_concentration": 0.60,
    "baseline_coverage": 0.90,
    "rare_max_count": 2,
    "rare_max_fraction": 0.05,
}

_CLIENT_FP_FIELDS = (
    "ja3",
    "ja3_hash",
    "client_ja3",
    "client_ja3_hash",
    "ssl.ja3",
)
_SERVER_FP_FIELDS = (
    "ja3s",
    "ja3s_hash",
    "server_ja3",
    "server_ja3_hash",
    "ssl.ja3s",
)


class Ja3FingerprintOutliersModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="ja3_fingerprint_outliers",
        name="JA3/JA3S Fingerprint Outliers",
        description=(
            "Detects rare TLS client/server JA3 or JA3S fingerprints that fall outside an established, "
            "stable fingerprint baseline for a configured network segment."
        ),
        category="security_analysis",
        required_logs=("ssl",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        segments = _segments(context.metadata)
        observations: dict[tuple[str, str], list[tuple[str, dict[str, Any]]]] = defaultdict(list)
        skipped_no_fingerprint = 0
        skipped_no_segment = 0

        for row in context.ssl:
            client_fp = _first_text(row, _CLIENT_FP_FIELDS)
            server_fp = _first_text(row, _SERVER_FP_FIELDS)
            if not client_fp and not server_fp:
                skipped_no_fingerprint += 1
                continue

            source_ip = _first_text(row, ("source_ip", "id.orig_h"))
            destination_ip = _first_text(row, ("destination_ip", "id.resp_h"))
            client_segment = _row_segment(row, "source") or _segment_for_ip(source_ip, segments)
            server_segment = _row_segment(row, "destination") or _segment_for_ip(destination_ip, segments)

            added = False
            if client_fp and client_segment:
                observations[("ja3", client_segment)].append((client_fp, row))
                added = True
            if server_fp and server_segment:
                observations[("ja3s", server_segment)].append((server_fp, row))
                added = True
            if not added:
                skipped_no_segment += 1

        findings: list[Finding] = []
        baselines_established = 0
        candidate_outliers = 0
        for (kind, segment), entries in sorted(observations.items()):
            baseline = _build_baseline(entries, policy)
            if baseline is None:
                continue
            baselines_established += 1
            outlier_fps = baseline["outliers"]
            for fingerprint in sorted(outlier_fps):
                rows = [row for fp, row in entries if fp == fingerprint]
                candidate_outliers += 1
                findings.append(
                    _finding(
                        kind=kind,
                        segment=segment,
                        fingerprint=fingerprint,
                        rows=rows,
                        baseline=baseline,
                        policy=policy,
                    )
                )

        affected = sorted({device for finding in findings for device in finding.devices})
        fingerprints_seen = sum(len(entries) for entries in observations.values())
        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "tls_events_evaluated": len(context.ssl),
                "fingerprint_observations": fingerprints_seen,
                "segment_fingerprint_baselines": baselines_established,
                "fingerprint_outlier_findings": len(findings),
                "candidate_outlier_fingerprints": candidate_outliers,
                "affected_devices": len(affected),
                "events_without_ja3_ja3s": skipped_no_fingerprint,
                "fingerprint_events_without_segment": skipped_no_segment,
            },
            evidence={
                "inspected_logs": ["ssl"] if context.ssl else [],
                "notes": [
                    "JA3/JA3S hashes are categorical fingerprints; the detector does not claim cryptographic or semantic distance between two hash values.",
                    "A finding requires a sufficiently large and stable per-segment baseline, plus a fingerprint that is both rare and outside the fingerprints covering the configured baseline fraction.",
                    "Rare fingerprints are not inherently malicious. Software updates, new devices, browser/runtime changes, TLS libraries, middleboxes, scanners, and administrative tools can legitimately introduce new fingerprints.",
                    "Client JA3 is baselined against the source segment; server JA3S is baselined against the destination segment.",
                    "The detector requires configured or explicitly enriched segment identity and does not invent segment boundaries from arbitrary IP prefixes.",
                    "Rendered evidence is capped at 10 representative TLS events while full counts and baseline statistics remain in metadata.",
                ],
                "policy": policy,
            },
            warnings=[],
        )


def _build_baseline(
    entries: list[tuple[str, dict[str, Any]]], policy: dict[str, float | int]
) -> dict[str, Any] | None:
    total = len(entries)
    if total < int(policy["minimum_segment_observations"]):
        return None
    counts = Counter(fp for fp, _ in entries)
    ordered = counts.most_common()
    dominant_fraction = ordered[0][1] / total if ordered else 0.0
    if dominant_fraction < float(policy["minimum_baseline_concentration"]):
        return None

    baseline_fps: list[str] = []
    covered = 0
    target = float(policy["baseline_coverage"])
    for fp, count in ordered:
        baseline_fps.append(fp)
        covered += count
        if covered / total >= target:
            break

    rare_max_count = int(policy["rare_max_count"])
    rare_max_fraction = float(policy["rare_max_fraction"])
    outliers = {
        fp
        for fp, count in counts.items()
        if fp not in baseline_fps and count <= rare_max_count and (count / total) <= rare_max_fraction
    }
    if not outliers:
        return {
            "total": total,
            "counts": counts,
            "dominant_fraction": dominant_fraction,
            "baseline_fingerprints": baseline_fps,
            "baseline_coverage_actual": covered / total,
            "outliers": set(),
        }
    return {
        "total": total,
        "counts": counts,
        "dominant_fraction": dominant_fraction,
        "baseline_fingerprints": baseline_fps,
        "baseline_coverage_actual": covered / total,
        "outliers": outliers,
    }


def _finding(
    *,
    kind: str,
    segment: str,
    fingerprint: str,
    rows: list[dict[str, Any]],
    baseline: dict[str, Any],
    policy: dict[str, float | int],
) -> Finding:
    count = len(rows)
    total = int(baseline["total"])
    fraction = count / total if total else 0.0
    devices, ports, pairs, timestamps = _provenance(rows[:_MAX_EVIDENCE])
    label = "JA3 client" if kind == "ja3" else "JA3S server"
    endpoint_role = "source/client" if kind == "ja3" else "destination/server"
    return Finding(
        title=f"{label} fingerprint outlier in segment {segment}",
        severity="low",
        summary=(
            f"Observed {count} TLS event(s) using {label} fingerprint {fingerprint} in segment '{segment}', "
            f"representing {fraction:.2%} of {total} fingerprint observations. The segment has a stable established "
            "fingerprint baseline and this value falls outside the fingerprints covering the normal baseline. "
            "This is an anomaly for review, not evidence by itself of malware or compromise."
        ),
        confidence="medium",
        detection_basis="derived",
        devices=devices,
        services=["TLS/SSL"],
        ports=ports,
        connection_pairs=pairs,
        flows=[dict(row) for row in rows[:_MAX_EVIDENCE]],
        subnets=[segment],
        timestamps=timestamps,
        tags=["tls", kind, "fingerprint-outlier", "segment-baseline"],
        metadata={
            "fingerprint_type": kind,
            "fingerprint": fingerprint,
            "segment": segment,
            "segment_endpoint_role": endpoint_role,
            "event_count": count,
            "segment_observation_count": total,
            "segment_fraction": fraction,
            "dominant_fingerprint_fraction": baseline["dominant_fraction"],
            "baseline_fingerprints": list(baseline["baseline_fingerprints"]),
            "baseline_coverage_actual": baseline["baseline_coverage_actual"],
            "baseline_minimum_observations": int(policy["minimum_segment_observations"]),
            "rare_max_count": int(policy["rare_max_count"]),
            "rare_max_fraction": float(policy["rare_max_fraction"]),
            "malicious_confirmed": False,
            "evidence_event_count": min(count, _MAX_EVIDENCE),
            "evidence_truncated": count > _MAX_EVIDENCE,
        },
    )


def _policy(metadata: dict[str, Any]) -> dict[str, float | int]:
    result: dict[str, float | int] = dict(_DEFAULT_POLICY)
    raw = metadata.get("ja3_outlier_policy")
    if not isinstance(raw, dict):
        raw = metadata.get("tls_fingerprint_policy")
    if isinstance(raw, dict):
        for key in _DEFAULT_POLICY:
            if key not in raw:
                continue
            try:
                value = float(raw[key])
            except (TypeError, ValueError):
                continue
            if key in {"minimum_segment_observations", "rare_max_count"}:
                result[key] = max(1, int(value))
            elif key in {"minimum_baseline_concentration", "baseline_coverage", "rare_max_fraction"}:
                result[key] = min(1.0, max(0.0, value))
    return result


def _segments(metadata: dict[str, Any]) -> list[tuple[ipaddress._BaseNetwork, str]]:
    result: list[tuple[ipaddress._BaseNetwork, str]] = []
    raw_segments = metadata.get("segments")
    if not isinstance(raw_segments, list):
        return result
    for item in raw_segments:
        if not isinstance(item, dict):
            continue
        cidr = item.get("cidr") or item.get("network") or item.get("subnet")
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            continue
        name = str(item.get("name") or item.get("id") or item.get("segment") or network)
        result.append((network, name))
    result.sort(key=lambda value: value[0].prefixlen, reverse=True)
    return result


def _segment_for_ip(value: str, segments: list[tuple[ipaddress._BaseNetwork, str]]) -> str:
    if not value:
        return ""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return ""
    for network, name in segments:
        if address.version == network.version and address in network:
            return name
    return ""


def _row_segment(row: dict[str, Any], side: str) -> str:
    keys = (
        ("source_segment", "orig_segment", "client_segment", "segment_orig")
        if side == "source"
        else ("destination_segment", "resp_segment", "server_segment", "segment_resp")
    )
    return _first_text(row, keys)


def _first_text(row: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = row.get(key)
        if value not in (None, "", "-"):
            return str(value).strip()
    return ""


def _provenance(rows: list[dict[str, Any]]) -> tuple[list[str], list[int], list[dict[str, Any]], list[float | str]]:
    devices: list[str] = []
    ports: set[int] = set()
    pairs: list[dict[str, Any]] = []
    timestamps: list[float | str] = []
    seen: set[tuple[str, str, int | None]] = set()
    for row in rows:
        source = _first_text(row, ("source_ip", "id.orig_h"))
        destination = _first_text(row, ("destination_ip", "id.resp_h"))
        port = _as_int(row.get("destination_port") or row.get("id.resp_p"))
        if source:
            devices.append(source)
        if destination:
            devices.append(destination)
        if port is not None:
            ports.add(port)
        key = (source, destination, port)
        if key not in seen:
            seen.add(key)
            pairs.append({"source": source, "destination": destination, "port": port, "protocol": "tcp", "service": "TLS/SSL"})
        ts = row.get("timestamp", row.get("ts"))
        if ts not in (None, ""):
            timestamps.append(ts)
    return _unique(devices), sorted(ports), pairs, timestamps


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
