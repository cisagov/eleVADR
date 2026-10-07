# Additional detector wave: 60 -> 65 modules

This checkpoint adds five detectors without changing the core Detection Context rule: observed Zeek traffic is evidence, not authorization.

| Module | Primary evidence | Authoritative context / policy | Key behavior |
| --- | --- | --- | --- |
| `arp_ip_mac_identity_change` | `arp.log` | `asset_inventory`, `arp_identity_policy` | Flags authoritative IP/MAC mismatch and rapid multi-MAC identity changes. Zeek-observed assets never become authoritative identity. |
| `unexpected_dhcp_server` | `dhcp.log` | trusted DHCP infrastructure -> `unexpected_dhcp_server_policy.expected_servers` | Flags Offer/ACK/NAK server responses outside explicitly trusted DHCP infrastructure. No trusted list means observation only, not an unexpected-server finding. |
| `ot_protocol_role_reversal` | `conn.log` | `ot_role_reversal_policy` | Learns responder/originator direction during a capture baseline and flags a baseline responder that later originates the same OT protocol. |
| `plc_rtu_peer_change` | `conn.log` | authoritative controller assets, `plc_rtu_peer_change_policy` | Flags post-baseline OT peers involving authoritative PLC/RTU/controller/IED assets. Observed communication is baseline evidence only; suppression requires explicit `allowed_pairs`. |
| `engineering_workstation_control_burst` | Modbus/DNP3/S7/CIP protocol logs | authoritative engineering-workstation assets, Control Authorization, `engineering_control_burst_policy` | Flags concentrated write/programming activity even when individual paths are authorized. Authorization is reported as context and does not automatically suppress a behavior burst. |

## Frontend integration

All five module IDs remain part of `ALL_DETECTION_MODULES`. At the time of Wave 1 this brought the registry to 65 modules; the current Wave 2 baseline contains 70. Advanced policy schemas and readiness guidance are present for all five modules. Findings use the existing explainability drawer and include module-specific legitimate-context guidance.

## Regression integration

Wave 1 established a 65-module package contract. Wave 2 established a 70-module package contract; the current package contract is 75 modules after Wave 3. Dataset 07 registry-wide state isolation, Dataset 10 scale behavior, and Dataset 14 mixed-OT acceptance exercise the current registry. A dedicated `new_detector_acceptance_runner` adds focused positive cases for each new detector.

Datasets 01-03 intentionally remain the original 60-detector live-PCAP baseline so historical finding counts and reference reports stay directly comparable. The standard gate labels that stage as the legacy 60-detector baseline.

## Raw-PCAP validation

Dataset 15 (`backend_bryan/regression/dataset15_runner.py`) validates all five modules from raw Ethernet packets through the pinned Zeek runtime rather than injecting normalized detector evidence. It also protects native Zeek Modbus function-name handling (`WRITE_SINGLE_REGISTER`) and the explicit ARP runtime policy used to produce `arp.log`.
