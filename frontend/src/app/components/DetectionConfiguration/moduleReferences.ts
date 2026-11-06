export interface DetectionModuleReference {
  title: string;
  source: string;
  url: string;
}

const NIST_OT: DetectionModuleReference = {
  title: "Guide to Operational Technology (OT) Security",
  source: "NIST SP 800-82 Rev. 3",
  url: "https://csrc.nist.gov/pubs/sp/800/82/r3/final",
};

const MITRE_ICS: DetectionModuleReference = {
  title: "ICS Techniques",
  source: "MITRE ATT&CK",
  url: "https://attack.mitre.org/techniques/ics/",
};

const ZEEK_LOGS: DetectionModuleReference = {
  title: "Zeek Log Files",
  source: "Zeek Documentation",
  url: "https://docs.zeek.org/en/current/logs/index.html",
};

const refs: Record<string, DetectionModuleReference> = {
  arp: {
    title: "An Ethernet Address Resolution Protocol",
    source: "IETF RFC 826",
    url: "https://datatracker.ietf.org/doc/html/rfc826",
  },
  bacnet: {
    title: "About the BACnet Standard",
    source: "BACnet Committee / ASHRAE",
    url: "https://bacnet.org/about-bacnet-standard/",
  },
  c2: {
    title: "Application Layer Protocol",
    source: "MITRE ATT&CK",
    url: "https://attack.mitre.org/techniques/T1071/",
  },
  bruteForce: {
    title: "Brute Force",
    source: "MITRE ATT&CK",
    url: "https://attack.mitre.org/techniques/T1110/",
  },
  sniffing: {
    title: "Network Sniffing",
    source: "MITRE ATT&CK",
    url: "https://attack.mitre.org/techniques/T1040/",
  },
  codesys: {
    title: "CODESYS Runtime",
    source: "CODESYS",
    url: "https://www.codesys.com/products/runtime/",
  },
  remoteServicesIcs: {
    title: "Remote Services",
    source: "MITRE ATT&CK for ICS",
    url: "https://attack.mitre.org/techniques/T0886/",
  },
  internetDevice: {
    title: "Internet Accessible Device",
    source: "MITRE ATT&CK for ICS",
    url: "https://attack.mitre.org/techniques/T0883/",
  },
  scan: {
    title: "Remote System Discovery",
    source: "MITRE ATT&CK for ICS",
    url: "https://attack.mitre.org/techniques/T0846/",
  },
  dns: {
    title: "Domain Names - Implementation and Specification",
    source: "IETF RFC 1035",
    url: "https://datatracker.ietf.org/doc/html/rfc1035",
  },
  dnsC2: {
    title: "Application Layer Protocol: DNS",
    source: "MITRE ATT&CK",
    url: "https://attack.mitre.org/techniques/T1071/004/",
  },
  tls: {
    title: "Guidelines for TLS Implementations",
    source: "NIST SP 800-52 Rev. 2",
    url: "https://csrc.nist.gov/pubs/sp/800/52/r2/final",
  },
  unauthorizedMessage: {
    title: "Unauthorized Message",
    source: "MITRE ATT&CK for ICS",
    url: "https://attack.mitre.org/techniques/T1692/",
  },
  modbus: {
    title: "Modbus Specifications",
    source: "Modbus Organization",
    url: "https://www.modbus.org/modbus-specifications",
  },
  dnp3: {
    title: "Overview of DNP3 Protocol",
    source: "DNP Users Group",
    url: "https://www.dnp.org/About/Overview-of-DNP3-Protocol",
  },
  enip: {
    title: "EtherNet/IP",
    source: "ODVA",
    url: "https://www.odva.org/technology-standards/key-technologies/ethernet-ip/",
  },
  multicast: {
    title: "Host Extensions for IP Multicasting",
    source: "IETF RFC 1112",
    url: "https://datatracker.ietf.org/doc/html/rfc1112",
  },
  exfil: {
    title: "Exfiltration Over Alternative Protocol",
    source: "MITRE ATT&CK",
    url: "https://attack.mitre.org/techniques/T1048/",
  },
  http: {
    title: "HTTP Semantics",
    source: "IETF RFC 9110",
    url: "https://datatracker.ietf.org/doc/html/rfc9110",
  },
  icmp: {
    title: "Internet Control Message Protocol",
    source: "IETF RFC 792",
    url: "https://datatracker.ietf.org/doc/html/rfc792",
  },
  nonAppProtocol: {
    title: "Non-Application Layer Protocol",
    source: "MITRE ATT&CK",
    url: "https://attack.mitre.org/techniques/T1095/",
  },
  ipv6: {
    title: "Internet Protocol, Version 6 (IPv6) Specification",
    source: "IETF RFC 8200",
    url: "https://datatracker.ietf.org/doc/html/rfc8200",
  },
  irc: {
    title: "Internet Relay Chat: Client Protocol",
    source: "IETF RFC 2812",
    url: "https://datatracker.ietf.org/doc/html/rfc2812",
  },
  asrep: {
    title: "Steal or Forge Kerberos Tickets: AS-REP Roasting",
    source: "MITRE ATT&CK",
    url: "https://attack.mitre.org/techniques/T1558/004/",
  },
  ldap: {
    title: "Lightweight Directory Access Protocol (LDAP)",
    source: "IETF RFC 4511",
    url: "https://datatracker.ietf.org/doc/html/rfc4511",
  },
  poisoning: {
    title: "LLMNR/NBT-NS Poisoning and SMB Relay",
    source: "MITRE ATT&CK",
    url: "https://attack.mitre.org/techniques/T1557/001/",
  },
  llmnr: {
    title: "Link-Local Multicast Name Resolution",
    source: "IETF RFC 4795",
    url: "https://datatracker.ietf.org/doc/html/rfc4795",
  },
  smb: {
    title: "SMB file server overview",
    source: "Microsoft Learn",
    url: "https://learn.microsoft.com/en-us/windows-server/storage/file-server/file-server-smb-overview",
  },
  smbRemote: {
    title: "Remote Services: SMB/Windows Admin Shares",
    source: "MITRE ATT&CK",
    url: "https://attack.mitre.org/techniques/T1021/002/",
  },
  niagara: {
    title: "Niagara Framework",
    source: "Tridium",
    url: "https://www.tridium.com/us/en/Products/niagara",
  },
  ntp: {
    title: "Network Time Protocol Version 4",
    source: "IETF RFC 5905",
    url: "https://datatracker.ietf.org/doc/html/rfc5905",
  },
  programDownload: {
    title: "Program Download",
    source: "MITRE ATT&CK for ICS",
    url: "https://attack.mitre.org/techniques/T0843/",
  },
  quic: {
    title: "QUIC: A UDP-Based Multiplexed and Secure Transport",
    source: "IETF RFC 9000",
    url: "https://datatracker.ietf.org/doc/html/rfc9000",
  },
  rdp: {
    title: "Remote Services: Remote Desktop Protocol",
    source: "MITRE ATT&CK",
    url: "https://attack.mitre.org/techniques/T1021/001/",
  },
  externalRemote: {
    title: "External Remote Services",
    source: "MITRE ATT&CK for ICS",
    url: "https://attack.mitre.org/techniques/T0822/",
  },
  dhcp: {
    title: "Dynamic Host Configuration Protocol",
    source: "IETF RFC 2131",
    url: "https://datatracker.ietf.org/doc/html/rfc2131",
  },
  s7: {
    title: "Security with SIMATIC Controllers",
    source: "Siemens",
    url: "https://support.industry.siemens.com/cs/attachments/90885010/90885010_Security_SIMATIC_Controller_V30_en.pdf",
  },
  smbSigning: {
    title: "SMB signing",
    source: "Microsoft Learn",
    url: "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing",
  },
  snmp: {
    title: "An Architecture for Describing SNMP Management Frameworks",
    source: "IETF RFC 3411",
    url: "https://datatracker.ietf.org/doc/html/rfc3411",
  },
  socks: {
    title: "SOCKS Protocol Version 5",
    source: "IETF RFC 1928",
    url: "https://datatracker.ietf.org/doc/html/rfc1928",
  },
  tcp: {
    title: "Transmission Control Protocol (TCP)",
    source: "IETF RFC 9293",
    url: "https://datatracker.ietf.org/doc/html/rfc9293",
  },
  upnp: {
    title: "UPnP Resources",
    source: "Open Connectivity Foundation",
    url: "https://openconnectivity.org/developer/specifications/upnp-resources/",
  },
  vlan: {
    title: "IEEE 802.1Q",
    source: "IEEE 802.1",
    url: "https://1.ieee802.org/tsn/802-1q/",
  },
  weird: {
    title: "Zeek Weird Framework",
    source: "Zeek Documentation",
    url: "https://docs.zeek.org/en/current/scripts/base/frameworks/notice/weird.zeek.html",
  },
};

const specific: Record<string, DetectionModuleReference[]> = {
  arp_ip_mac_identity_change: [refs.arp],
  arp_l2_reconnaissance: [refs.arp, refs.scan],
  bacnet_discovery_anomalies: [refs.bacnet, refs.scan],
  beaconing_c2_communication: [refs.c2],
  brute_force_authentication: [refs.bruteForce],
  cleartext_credentials: [refs.sniffing],
  codesys_runtime_exposure: [refs.codesys, refs.internetDevice],
  control_system_enterprise_non_dmz: [MITRE_ICS],
  controller_communication_jitter: [ZEEK_LOGS],
  cross_purdue_level_traffic: [MITRE_ICS],
  database_service_exposed: [refs.internetDevice],
  deprecated_insecure_services_protocols: [NIST_OT],
  deprecated_vpn_protocol: [refs.externalRemote],
  dns_source_drift: [refs.dns],
  dns_tunneling_exfiltration: [refs.dns, refs.dnsC2],
  encrypted_session_fingerprint_change: [refs.tls, ZEEK_LOGS],
  engineering_tools_cleartext: [NIST_OT, refs.sniffing],
  engineering_workstation_control_burst: [refs.unauthorizedMessage],
  enip_cip_write_session_abuses: [refs.enip, refs.unauthorizedMessage],
  excessive_broadcast_multicast_ot: [refs.multicast],
  file_extraction_sensitive_types: [refs.exfil],
  high_fan_in_out: [refs.scan],
  http_user_agent_anomalies: [refs.http],
  iccp_tase2_detected: [NIST_OT],
  icmp_data_channel: [refs.icmp, refs.nonAppProtocol],
  ics_protocol_error_spike: [NIST_OT, ZEEK_LOGS],
  ics_write_operations: [refs.modbus, refs.dnp3, refs.unauthorizedMessage],
  internet_exposed_ics: [refs.internetDevice],
  ipv6_traffic_ot: [refs.ipv6],
  irc_traffic_detected: [refs.irc, refs.c2],
  ja3_fingerprint_outliers: [refs.tls, ZEEK_LOGS],
  kerberos_asrep_roastable_accounts: [refs.asrep],
  large_outbound_http_uploads: [refs.http, refs.exfil],
  ldap_cleartext_anonymous_cross_segment: [refs.ldap],
  llmnr_nbtns_mdns_poisoning_signals: [refs.poisoning, refs.llmnr],
  netbios_smbv1_exposure: [refs.smb, refs.smbRemote],
  new_ot_conversation_pair: [MITRE_ICS, ZEEK_LOGS],
  new_service_emergence_ot: [NIST_OT, ZEEK_LOGS],
  niagara_fox_detected: [refs.niagara],
  ntp_internet_multi_dest_ot: [refs.ntp],
  ntp_source_drift: [refs.ntp],
  ot_asset_gone_silent: [NIST_OT, ZEEK_LOGS],
  ot_external_dns_resolver: [refs.dns],
  ot_management_certificate_risk: [refs.tls],
  ot_outbound_internet_any_protocol: [NIST_OT, MITRE_ICS],
  ot_protocol_exposure: [refs.internetDevice, MITRE_ICS],
  ot_protocol_role_reversal: [NIST_OT, ZEEK_LOGS],
  plc_program_logic_firmware_update: [refs.programDownload],
  plc_rtu_peer_change: [NIST_OT, ZEEK_LOGS],
  polling_cadence_disruption: [NIST_OT, ZEEK_LOGS],
  port_host_scanning: [refs.scan],
  protocol_unexpected_high_risk_port: [NIST_OT, ZEEK_LOGS],
  public_to_public_traffic: [NIST_OT],
  quic_ot_segments: [refs.quic],
  rdp_nla_disabled: [refs.rdp],
  remote_access_session_anomaly: [refs.remoteServicesIcs],
  remote_access_tool_exposure: [refs.externalRemote, refs.remoteServicesIcs],
  rogue_dhcp_static_ot: [refs.dhcp],
  s7comm_unauthorized_write_stop: [refs.s7, refs.unauthorizedMessage],
  service_disappearance_replacement: [NIST_OT, ZEEK_LOGS],
  smb_admin_share_access: [refs.smbRemote, refs.smb],
  smb_signing_disabled_ntlmv1: [refs.smbSigning, refs.smb],
  snmp_write_ot_devices: [refs.snmp, refs.unauthorizedMessage],
  socks_open_proxy_behavior: [refs.socks],
  tcp_reset_abort_surge: [refs.tcp],
  tls_certificate_anomalies: [refs.tls],
  tls_sni_certificate_reuse: [refs.tls, ZEEK_LOGS],
  unexpected_dhcp_server: [refs.dhcp],
  unexpected_multicast_behavior: [refs.multicast],
  unknown_rogue_devices: [NIST_OT, refs.scan],
  unusual_outbound_data_volume: [refs.exfil],
  upnp_ssdp_igd_port_mapping: [refs.upnp],
  vlan_tag_mismatch_double_tag: [refs.vlan],
  weak_broken_tls_ssl: [refs.tls],
  weird_protocol_violations: [refs.weird, ZEEK_LOGS],
};

export const DETECTION_MODULE_REFERENCES: Record<
  string,
  DetectionModuleReference[]
> = Object.fromEntries(
  Object.entries(specific).map(([id, items]) => {
    const merged = [NIST_OT, ...items];
    const unique = merged.filter(
      (item, index, array) =>
        array.findIndex((candidate) => candidate.url === item.url) === index,
    );
    return [id, unique];
  }),
);
