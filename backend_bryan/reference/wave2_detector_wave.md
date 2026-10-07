# Wave 2 detector expansion: 65 -> 70 modules

Wave 2 adds five focused network/OT behavior detectors:

- `dns_source_drift` — trusted DNS infrastructure plus post-baseline resolver change detection.
- `ntp_source_drift` — trusted NTP infrastructure plus post-baseline time-source change detection.
- `arp_l2_reconnaissance` — rapid ARP probing across many distinct IPv4 targets.
- `unexpected_multicast_behavior` — OT-originated multicast to groups outside explicit allowed-group policy.
- `tcp_reset_abort_surge` — reset/rejected/aborted TCP-session bursts against a destination.

Policy remains authoritative. Observed DNS/NTP servers or multicast groups never become trusted/allowed merely because they were seen. Wave 2 established a 70-module registry; the current registry contains 75 modules after Wave 3. `wave2_detector_acceptance_runner` provides focused positive acceptance coverage and the registry-wide state/scale gates now exercise all 75 modules.

## Raw-PCAP validation

Dataset 16 (`backend_bryan.regression.dataset16_runner`) provides packet-level Zeek validation for all five Wave 2 modules. It also freezes the `zeek_state` integration contract used by `tcp_reset_abort_surge`.
