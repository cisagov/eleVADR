# Detection Context v3 -> AnalysisContext.metadata contract

This document describes the explicit handoff contract implemented in `backend_bryan/adapters/detection_context_adapter.py`.

## Shared normalized metadata

Frontend | Detector metadata
--- | ---
`segments[].purdueLevel` | `segments[].purdue_level`
`segments[].vlanId` | `segments[].vlan_id`
`segments[].dhcpAllowed` | `segments[].dhcp_allowed`
`segments[].ipv6Allowed=false` | `segments[].ipv4_only=true`
`assets[].assetType` | `asset_inventory[].asset_type`
`assets[].macAddresses` | `asset_inventory[].mac_addresses` and `macs`
`assets[].purdueLevel` | `asset_inventory[].purdue_level`

Scanner-only observed fields remain under `detection_context_observations` and are not copied into policy declarations.

## Capture Scope

- `captureScope.internalIcsOnlyExpected` -> `public_to_public_policy.internal_ics_only_expected`
- `captureScope.ipv4OnlyExpected` -> `ipv6_ot_policy.ipv4_only_expected`
- global IPv4-only expectation -> `ipv6_ot_policy.scope_all_connections=true`
- an OT segment with `ipv6Allowed=false` contributes to `ipv6_ot_policy.ipv4_only_expected=true` without asserting global scope.

`dedicatedOtSensor` remains frontend/site context unless a detector has a documented policy field that consumes it. It is not blindly copied to unrelated policies.

## Trusted Infrastructure

- DNS -> `ot_dns_policy.trusted_resolvers`
- NTP -> `ntp_ot_policy.trusted_servers`
- DHCP -> `dhcp_ot_policy.expected_servers`
- static/DHCP-prohibited segments -> `dhcp_ot_policy.static_segments`
- management hosts -> `ot_certificate_policy.management_hosts`

Management hosts are **not** automatically added to every detector's allowlist.

## Explicit communications policy

`allowedSegmentPairs` is compiled to `allowed_segment_pairs` only for documented consumers:

- `control_system_enterprise_policy`
- `database_exposure_policy`
- `netbios_smbv1_policy`

`communicationPairs` from Zeek are never compiled into these exceptions.

## Approved external destinations

Explicit approved destinations are mapped to:

- `ot_outbound_internet_policy.allowed_external_destinations`
- `internet_exposed_ics_policy.allowed_external_destinations`
- `file_transfer_policy.approved_external_destinations`

## Authorized Control Actions

Only explicit `authorizedControlActions` create high-risk authorization policy:

- Modbus/DNP3 -> `ics_write_policy.allowed_paths`
- S7comm -> `s7comm_control_policy.allowed_paths`
- EtherNet/IP -> `enip_cip_policy.allowed_write_paths`
- explicit control relationships -> `plc_program_firmware_policy.allowed_pairs`

### Non-mapping invariant

An observed Zeek row such as:

```json
{"sourceIp":"10.1.1.10","destinationIp":"10.1.1.20","protocol":"s7comm"}
```

must **not** create `s7comm_control_policy`, `ics_write_policy`, or `enip_cip_policy` authorization.

## Advanced Module Overrides

Advanced overrides are explicit user policy and overlay first-class compiled values for detector modules with a known policy namespace. This intentionally allows expert policy to override a generated default such as `internal_ics_only_expected`.

Unknown module IDs are not guessed into arbitrary metadata namespaces.
