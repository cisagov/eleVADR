# eleVADR Application Regression Test Pack

This pack contains three synthetic PCAPs and three directly loadable canonical eleVADR JSON reports. The PCAP and JSON in each numbered pair represent the same test theme, but the JSON is generated from deterministic normalized Zeek-like records so it can serve as a stable UI regression fixture.

## Test cases

### 01 — Mixed OT baseline
Exercises PCAP context discovery, DNS/NTP infrastructure, Modbus observation, internal HTTP, OT/IT asset rendering, and a relatively low-noise report. Look for incorrect context inference, duplicate assets/segments, bad protocol labeling, or unexpected policy authorization.

### 02 — Legacy / high-risk services
Exercises FTP/Telnet cleartext behavior, SMB/NetBIOS, database/VNC/PPTP/IRC port indicators, repeated failed RDP attempts, many simultaneous findings, severity/filter UI, and large result drill-down. Look for duplicate findings, poor grouping, broken filtering, layout overflow, or inconsistent friendly names.

### 03 — Outbound + IPv6 + QUIC + ICMP
Exercises a 12 MiB outbound HTTP POST, QUIC/UDP 443, 12 independently timed uniform ICMP echo records, IPv6 OT traffic, IPv4-only/internal-ICS policy assumptions, external destinations, and mixed address-family rendering. The upload deliberately exceeds the detector default 10 MiB threshold, and the ICMP events are spaced 65 seconds apart so Zeek can expose independently timed connection records instead of aggregating the whole train into one row. Look for IPv6 formatting bugs, external/internal classification errors, long-running progress issues, and report provenance/export problems.

## Companion Detection Context profiles

Each PCAP now has a matching Detection Context v3 profile. The profiles are valid frontend profile exports and select all 60 detector modules. They intentionally describe known site context without approving the suspicious behavior that each capture is meant to exercise.

- `01_mixed_ot_baseline.pcap` → `01_mixed_ot_baseline_context.json`
- `02_legacy_high_risk.pcap` → `02_legacy_high_risk_context.json`
- `03_outbound_ipv6_quic_icmp.pcap` → `03_outbound_ipv6_quic_icmp_context.json`

Suggested PCAP workflow: choose the PCAP, let Context Discovery complete, create/open a Detection Context, use **Load Profile** to load the matching `_context.json`, review the merged observations, then run the full analysis.

## Stable JSON fixture summary

- **01_mixed_ot_baseline.json**: 5 finding(s) across 4 module(s).
  Modules with findings: cross_purdue_level_traffic, deprecated_insecure_services_protocols, ot_protocol_exposure, unknown_rogue_devices
- **02_legacy_high_risk.json**: 18 finding(s) across 11 module(s).
  Modules with findings: brute_force_authentication, cleartext_credentials, cross_purdue_level_traffic, database_service_exposed, deprecated_insecure_services_protocols, deprecated_vpn_protocol, irc_traffic_detected, netbios_smbv1_exposure, protocol_unexpected_high_risk_port, remote_access_tool_exposure, unknown_rogue_devices
- **03_outbound_ipv6_quic_icmp.json**: 11 finding(s) across 11 module(s).
  Modules with findings: cross_purdue_level_traffic, deprecated_insecure_services_protocols, http_user_agent_anomalies, icmp_data_channel, internet_exposed_ics, ipv6_traffic_ot, large_outbound_http_uploads, new_ot_conversation_pair, ot_outbound_internet_any_protocol, quic_ot_segments, unusual_outbound_data_volume

## Suggested workflow

1. Load each JSON directly and inspect every report section, filters, printing/export, responsive layout, and finding drill-down.
2. Load each PCAP through the PCAP workflow, let Context Discovery finish, create/select a context, then run full analysis.
3. Compare the *themes* of the generated PCAP report with its paired JSON fixture. Exact finding counts can differ because the PCAP path depends on the installed Zeek version and protocol analyzers.
4. For case 03, specifically watch Docker/Zeek live progress and elapsed-time behavior.

All network traffic is synthetic and uses private/test-oriented hosts except well-known public resolver IPs (1.1.1.1 and 8.8.8.8), which are only encoded in the offline PCAP and are never contacted.

## Dataset 03 regression targets added in this revision

- ICMP communication-pair merging must treat missing/null destination port and Zeek synthetic port `0` as the same path for ICMP, while preserving the richer imported `service: "icmp"`.
- The PCAP contains 12 independently timed ICMP echo records at 65-second intervals so `icmp_data_channel` can evaluate event timing without inventing per-packet timestamps from an aggregated conn row.
- The HTTP POST body is 12 MiB, intentionally above the default 10 MiB `large_outbound_http_uploads` threshold.
