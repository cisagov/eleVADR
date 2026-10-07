# Module policy namespace mapping

This is the explicit module-ID -> `AnalysisContext.metadata` policy namespace map used by the isolated backend reference adapter.

| Module ID | Policy namespace |
| --- | --- |
| `bacnet_discovery_anomalies` | `bacnet_discovery_policy` |
| `codesys_runtime_exposure` | `codesys_runtime_policy` |
| `control_system_enterprise_non_dmz` | `control_system_enterprise_policy` |
| `cross_purdue_level_traffic` | `purdue_policy` |
| `database_service_exposed` | `database_exposure_policy` |
| `deprecated_vpn_protocol` | `deprecated_vpn_policy` |
| `engineering_tools_cleartext` | `engineering_cleartext_policy` |
| `enip_cip_write_session_abuses` | `enip_cip_policy` |
| `excessive_broadcast_multicast_ot` | `broadcast_multicast_ot_policy` |
| `file_extraction_sensitive_types` | `file_transfer_policy` |
| `high_fan_in_out` | `fan_in_out_policy` |
| `http_user_agent_anomalies` | `http_user_agent_policy` |
| `iccp_tase2_detected` | `iccp_tase2_policy` |
| `icmp_data_channel` | `icmp_data_channel_policy` |
| `ics_protocol_error_spike` | `ics_protocol_error_policy` |
| `ics_write_operations` | `ics_write_policy` |
| `internet_exposed_ics` | `internet_exposed_ics_policy` |
| `ipv6_traffic_ot` | `ipv6_ot_policy` |
| `irc_traffic_detected` | `irc_traffic_policy` |
| `ja3_fingerprint_outliers` | `ja3_outlier_policy` |
| `large_outbound_http_uploads` | `http_upload_policy` |
| `llmnr_nbtns_mdns_poisoning_signals` | `name_resolution_poisoning_policy` |
| `netbios_smbv1_exposure` | `netbios_smbv1_policy` |
| `new_ot_conversation_pair` | `ot_comm_matrix_policy` |
| `new_service_emergence_ot` | `service_baseline_policy` |
| `niagara_fox_detected` | `niagara_fox_policy` |
| `ntp_internet_multi_dest_ot` | `ntp_ot_policy` |
| `ot_asset_gone_silent` | `ot_asset_silence_policy` |
| `ot_external_dns_resolver` | `ot_dns_policy` |
| `ot_management_certificate_risk` | `ot_certificate_policy` |
| `ot_outbound_internet_any_protocol` | `ot_outbound_internet_policy` |
| `plc_program_logic_firmware_update` | `plc_program_firmware_policy` |
| `public_to_public_traffic` | `public_to_public_policy` |
| `quic_ot_segments` | `quic_ot_policy` |
| `remote_access_tool_exposure` | `remote_access_tool_policy` |
| `rogue_dhcp_static_ot` | `dhcp_ot_policy` |
| `s7comm_unauthorized_write_stop` | `s7comm_control_policy` |
| `snmp_write_ot_devices` | `snmp_write_policy` |
| `socks_open_proxy_behavior` | `proxy_behavior_policy` |
| `unusual_outbound_data_volume` | `outbound_volume_policy` |
| `vlan_tag_mismatch_double_tag` | `vlan_policy` |
