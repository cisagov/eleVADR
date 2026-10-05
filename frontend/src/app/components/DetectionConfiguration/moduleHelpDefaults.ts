/**
 * Audited defaults for numeric fields exposed by ADVANCED_POLICY_SCHEMA_BY_MODULE.
 *
 * Values in this file are verified against the corresponding detector implementation
 * by backend_bryan/tests/test_module_help_accuracy.py. Keep this map implementation-
 * backed; do not add illustrative or recommended values here.
 */
export const MODULE_HELP_NUMERIC_DEFAULTS: Record<string, Record<string, number>> = {
  arp_l2_reconnaissance: { window_seconds: 60, minimum_targets: 20 },
  dns_source_drift: { baseline_seconds: 300 },
  ntp_source_drift: { baseline_seconds: 300 },
  tcp_reset_abort_surge: { window_seconds: 60, minimum_events: 10, minimum_failure_ratio: 0.6 },
  unexpected_multicast_behavior: { minimum_flows: 3 },
  arp_ip_mac_identity_change: { change_window_seconds: 300 },
  engineering_workstation_control_burst: { window_seconds: 60, minimum_operations: 10 },
  ot_protocol_role_reversal: { baseline_seconds: 300, minimum_baseline_responder_events: 2 },
  plc_rtu_peer_change: { baseline_seconds: 300 },
  deprecated_vpn_protocol: { correlation_window_seconds: 120 },
  ics_protocol_error_spike: {
    baseline_seconds: 300,
    window_seconds: 60,
    min_events_per_window: 10,
    min_errors_per_window: 3,
    min_error_ratio: 0.25,
    baseline_multiplier: 3,
    min_baseline_events: 10,
  },
  ntp_internet_multi_dest_ot: { min_external_servers: 2 },
  ot_external_dns_resolver: { min_queries: 1 },
  ot_outbound_internet_any_protocol: { min_flows: 1 },
  public_to_public_traffic: { min_flows: 1 },
  rogue_dhcp_static_ot: { offer_window_seconds: 15 },
  snmp_write_ot_devices: { min_set_operations: 1 },
  encrypted_session_fingerprint_change: { baseline_seconds: 300, minimum_baseline_observations: 3 },
  remote_access_session_anomaly: { baseline_seconds: 300, minimum_new_targets: 2 },
  service_disappearance_replacement: { baseline_seconds: 300, minimum_baseline_observations: 3 },
  polling_cadence_disruption: { baseline_seconds: 300, minimum_baseline_observations: 5, interval_change_ratio: 0.5 },
  controller_communication_jitter: {
    baseline_seconds: 300,
    minimum_baseline_observations: 6,
    jitter_multiplier: 3,
    minimum_post_jitter_ratio: 0.25,
  },
};
