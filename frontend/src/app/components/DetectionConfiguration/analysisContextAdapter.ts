import { ADVANCED_POLICY_SCHEMA_BY_MODULE } from "./advancedPolicySchema";
import { ALL_DETECTION_MODULES } from "./moduleCatalog";
import {
  AuthorizedControlAction,
  DetectionConfigurationProfile,
} from "./types";

export type AnalysisContextMetadata = Record<string, unknown>;

/** Canonical detector metadata policy block used for modulePolicies overrides. */
export const MODULE_POLICY_NAMESPACE: Partial<
  Record<(typeof ALL_DETECTION_MODULES)[number], string>
> = {
  bacnet_discovery_anomalies: "bacnet_discovery_policy",
  codesys_runtime_exposure: "codesys_runtime_policy",
  control_system_enterprise_non_dmz: "control_system_enterprise_policy",
  cross_purdue_level_traffic: "purdue_policy",
  database_service_exposed: "database_exposure_policy",
  deprecated_vpn_protocol: "deprecated_vpn_policy",
  engineering_tools_cleartext: "engineering_cleartext_policy",
  enip_cip_write_session_abuses: "enip_cip_policy",
  excessive_broadcast_multicast_ot: "broadcast_multicast_ot_policy",
  file_extraction_sensitive_types: "file_transfer_policy",
  high_fan_in_out: "fan_in_out_policy",
  http_user_agent_anomalies: "http_user_agent_policy",
  iccp_tase2_detected: "iccp_tase2_policy",
  icmp_data_channel: "icmp_data_channel_policy",
  ics_protocol_error_spike: "ics_protocol_error_policy",
  ics_write_operations: "ics_write_policy",
  internet_exposed_ics: "internet_exposed_ics_policy",
  ipv6_traffic_ot: "ipv6_ot_policy",
  irc_traffic_detected: "irc_traffic_policy",
  ja3_fingerprint_outliers: "ja3_outlier_policy",
  large_outbound_http_uploads: "http_upload_policy",
  llmnr_nbtns_mdns_poisoning_signals: "name_resolution_poisoning_policy",
  netbios_smbv1_exposure: "netbios_smbv1_policy",
  new_ot_conversation_pair: "ot_comm_matrix_policy",
  new_service_emergence_ot: "service_baseline_policy",
  niagara_fox_detected: "niagara_fox_policy",
  ntp_internet_multi_dest_ot: "ntp_ot_policy",
  ot_asset_gone_silent: "ot_asset_silence_policy",
  ot_external_dns_resolver: "ot_dns_policy",
  ot_management_certificate_risk: "ot_certificate_policy",
  ot_outbound_internet_any_protocol: "ot_outbound_internet_policy",
  plc_program_logic_firmware_update: "plc_program_firmware_policy",
  public_to_public_traffic: "public_to_public_policy",
  quic_ot_segments: "quic_ot_policy",
  remote_access_tool_exposure: "remote_access_tool_policy",
  rogue_dhcp_static_ot: "dhcp_ot_policy",
  s7comm_unauthorized_write_stop: "s7comm_control_policy",
  snmp_write_ot_devices: "snmp_write_policy",
  socks_open_proxy_behavior: "proxy_behavior_policy",
  unusual_outbound_data_volume: "outbound_volume_policy",
  vlan_tag_mismatch_double_tag: "vlan_policy",
};

const HOST_ALLOW_MODULES = [
  "codesys_runtime_exposure",
  "database_service_exposed",
  "deprecated_vpn_protocol",
  "iccp_tase2_detected",
  "ics_protocol_error_spike",
  "irc_traffic_detected",
  "netbios_smbv1_exposure",
  "niagara_fox_detected",
  "remote_access_tool_exposure",
] as const;

const HOST_IGNORE_MODULES = [
  "new_ot_conversation_pair",
  "new_service_emergence_ot",
  "ot_asset_gone_silent",
] as const;

const SEGMENT_PAIR_MODULES = [
  "control_system_enterprise_non_dmz",
  "database_service_exposed",
  "netbios_smbv1_exposure",
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function mergePolicy(
  metadata: AnalysisContextMetadata,
  key: string,
  patch: Record<string, unknown>,
): void {
  const current = isRecord(metadata[key])
    ? (metadata[key] as Record<string, unknown>)
    : {};
  metadata[key] = { ...current, ...patch };
}

function nonEmpty(values: string[]): string[] {
  return [...new Set(values.map((x) => x.trim()).filter(Boolean))];
}

function controlPath(action: AuthorizedControlAction): Record<string, unknown> {
  return {
    source: action.source,
    destination: action.destination,
    ...(action.allowedOperations.length
      ? { allowed_operations: [...action.allowedOperations] }
      : {}),
    ...(action.allowedFunctionCodes.length
      ? { allowed_function_codes: [...action.allowedFunctionCodes] }
      : {}),
  };
}

/**
 * Compile a frontend Detection Context v3 profile to the metadata dictionary
 * consumed by elevadr_modules.models.AnalysisContext.
 *
 * Policy is compiled deliberately. Scanner observations are retained under
 * detection_context_observations and never promoted to allowlists merely
 * because they were observed.
 */
export function compileDetectionContextMetadata(
  profile: DetectionConfigurationProfile,
): AnalysisContextMetadata {
  const metadata: AnalysisContextMetadata = {
    detection_context_schema_version: profile.schemaVersion,
    detection_context_profile_id: profile.id,
    detection_context_profile_name: profile.name,
    segments_source: "detection_context_profile",
    asset_inventory_source: "detection_context_profile",
    segments: profile.segments.map((segment) => ({
      name: segment.name,
      cidr: segment.cidr,
      role: segment.role,
      ...(segment.purdueLevel ? { purdue_level: segment.purdueLevel } : {}),
      ...(segment.vlanId !== undefined ? { vlan_id: segment.vlanId } : {}),
      addressing: segment.addressing,
      ...(segment.dhcpAllowed !== undefined
        ? { dhcp_allowed: segment.dhcpAllowed }
        : {}),
      ...(segment.ipv6Allowed !== undefined
        ? {
            ipv6_allowed: segment.ipv6Allowed,
            ipv4_only: segment.ipv6Allowed === false,
          }
        : {}),
    })),
    asset_inventory: profile.assets.map((asset) => ({
      ip: asset.ip,
      ips: asset.ip ? [asset.ip] : [],
      ...(asset.hostname
        ? { hostname: asset.hostname, name: asset.hostname }
        : {}),
      mac_addresses: [...asset.macAddresses],
      macs: [...asset.macAddresses],
      asset_type: asset.assetType,
      role: asset.role,
      ...(asset.segment ? { segment: asset.segment } : {}),
      ...(asset.purdueLevel ? { purdue_level: asset.purdueLevel } : {}),
      services: [...asset.services],
      ports: [...asset.ports],
    })),
    detection_context_observations: {
      scan: { ...profile.scan },
      communications: profile.communicationPairs.map((pair) => ({
        source: pair.sourceIp,
        destination: pair.destinationIp,
        ...(pair.protocol ? { protocol: pair.protocol } : {}),
        ...(pair.destinationPort !== undefined
          ? { destination_port: pair.destinationPort }
          : {}),
        ...(pair.service ? { service: pair.service } : {}),
        ...(pair.description ? { description: pair.description } : {}),
        source_kind: pair.source,
        confidence: pair.confidence,
      })),
      segments: profile.segments.map((segment) => ({
        id: segment.id,
        ...(segment.observedDhcp !== undefined
          ? { dhcp_observed: segment.observedDhcp }
          : {}),
        ...(segment.observedOtProtocols?.length
          ? { ot_protocols_observed: [...segment.observedOtProtocols] }
          : {}),
        ...(segment.observedVlanIds?.length
          ? { vlan_ids_observed: [...segment.observedVlanIds] }
          : {}),
      })),
    },
  };

  // Capture-scope policy mappings.
  mergePolicy(metadata, "public_to_public_policy", {
    internal_ics_only_expected: profile.captureScope.internalIcsOnlyExpected,
  });
  const segmentIpv4Only = profile.segments.some(
    (s) => s.role === "ot" && s.ipv6Allowed === false,
  );
  mergePolicy(metadata, "ipv6_ot_policy", {
    ipv4_only_expected:
      profile.captureScope.ipv4OnlyExpected || segmentIpv4Only,
    scope_all_connections: profile.captureScope.ipv4OnlyExpected,
  });

  // Trusted infrastructure maps only to semantically corresponding detector policies.
  const dns = nonEmpty(
    profile.infrastructure.filter((x) => x.kind === "dns").map((x) => x.value),
  );
  const ntp = nonEmpty(
    profile.infrastructure.filter((x) => x.kind === "ntp").map((x) => x.value),
  );
  const dhcp = nonEmpty(
    profile.infrastructure.filter((x) => x.kind === "dhcp").map((x) => x.value),
  );
  const management = nonEmpty(
    profile.infrastructure
      .filter((x) => x.kind === "management")
      .map((x) => x.value),
  );
  if (dns.length)
    mergePolicy(metadata, "ot_dns_policy", { trusted_resolvers: dns });
  if (ntp.length)
    mergePolicy(metadata, "ntp_ot_policy", { trusted_servers: ntp });
  const staticSegments = nonEmpty(
    profile.segments
      .filter((x) => x.addressing === "static" || x.dhcpAllowed === false)
      .flatMap((x) => [x.name, x.cidr]),
  );
  if (dhcp.length || staticSegments.length)
    mergePolicy(metadata, "dhcp_ot_policy", {
      expected_servers: dhcp,
      static_segments: staticSegments,
    });
  if (management.length)
    mergePolicy(metadata, "ot_certificate_policy", {
      management_hosts: management,
    });

  // Explicit policy lists. Generic observed communications are intentionally not mapped to allowed_pairs.
  const allowedHosts = nonEmpty(profile.allowedHosts);
  if (allowedHosts.length) {
    for (const moduleId of HOST_ALLOW_MODULES) {
      const key = MODULE_POLICY_NAMESPACE[moduleId];
      if (key) mergePolicy(metadata, key, { allowed_hosts: allowedHosts });
    }
    for (const moduleId of HOST_IGNORE_MODULES) {
      const key = MODULE_POLICY_NAMESPACE[moduleId];
      if (key) mergePolicy(metadata, key, { ignored_hosts: allowedHosts });
    }
  }

  const allowedSegmentPairs = profile.allowedSegmentPairs.map((pair) => ({
    source: pair.sourceSegment,
    destination: pair.destinationSegment,
  }));
  if (allowedSegmentPairs.length) {
    for (const moduleId of SEGMENT_PAIR_MODULES) {
      const key = MODULE_POLICY_NAMESPACE[moduleId];
      if (key)
        mergePolicy(metadata, key, {
          allowed_segment_pairs: allowedSegmentPairs,
        });
    }
  }

  const external = nonEmpty(profile.approvedExternalDestinations);
  if (external.length) {
    mergePolicy(metadata, "ot_outbound_internet_policy", {
      allowed_external_destinations: external,
    });
    mergePolicy(metadata, "internet_exposed_ics_policy", {
      allowed_external_destinations: external,
    });
    mergePolicy(metadata, "file_transfer_policy", {
      approved_external_destinations: external,
    });
  }

  // High-risk control authorization comes only from Authorized Control Actions.
  const modbusDnp3 = profile.authorizedControlActions.filter(
    (x) => x.protocol === "modbus" || x.protocol === "dnp3",
  );
  if (modbusDnp3.length) {
    mergePolicy(metadata, "ics_write_policy", {
      allowed_paths: modbusDnp3.map((action) => ({
        protocol: action.protocol,
        ...controlPath(action),
      })),
    });
  }
  const s7 = profile.authorizedControlActions.filter(
    (x) => x.protocol === "s7comm",
  );
  if (s7.length)
    mergePolicy(metadata, "s7comm_control_policy", {
      allowed_paths: s7.map(controlPath),
    });
  const enip = profile.authorizedControlActions.filter(
    (x) => x.protocol === "enip",
  );
  if (enip.length)
    mergePolicy(metadata, "enip_cip_policy", {
      allowed_write_paths: enip.map((action) => ({
        source: action.source,
        destination: action.destination,
        ...(action.allowedFunctionCodes.length
          ? { allowed_service_codes: [...action.allowedFunctionCodes] }
          : {}),
      })),
    });
  if (profile.authorizedControlActions.length) {
    mergePolicy(metadata, "plc_program_firmware_policy", {
      allowed_pairs: profile.authorizedControlActions.map((action) => ({
        source: action.source,
        destination: action.destination,
        protocols: [action.protocol],
        ...(action.allowedOperations.length
          ? { operations: [...action.allowedOperations] }
          : {}),
      })),
    });
  }

  // Advanced overrides are explicit user policy and therefore overlay first-class compiled values.
  for (const [moduleId, rawOverride] of Object.entries(
    profile.modulePolicies,
  )) {
    if (!isRecord(rawOverride)) continue;
    const namespace =
      MODULE_POLICY_NAMESPACE[moduleId as keyof typeof MODULE_POLICY_NAMESPACE];
    if (namespace) mergePolicy(metadata, namespace, rawOverride);
  }

  return metadata;
}
