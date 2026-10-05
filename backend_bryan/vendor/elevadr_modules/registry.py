from __future__ import annotations

from elevadr_modules.modules.base import AnalysisModule
from elevadr_modules.modules.cleartext_credentials import CleartextCredentialsModule
from elevadr_modules.modules.deprecated_insecure_services_protocols import (
    DeprecatedInsecureServicesProtocolsModule,
)
from elevadr_modules.modules.weak_broken_tls_ssl import WeakBrokenTlsSslModule
from elevadr_modules.modules.tls_certificate_anomalies import TlsCertificateAnomaliesModule
from elevadr_modules.modules.beaconing_c2 import BeaconingC2Module
from elevadr_modules.modules.port_host_scanning import PortHostScanningModule
from elevadr_modules.modules.brute_force_authentication import BruteForceAuthenticationModule
from elevadr_modules.modules.dns_tunneling_exfiltration import DnsTunnelingExfiltrationModule
from elevadr_modules.modules.ot_protocol_exposure import OtProtocolExposureModule
from elevadr_modules.modules.cross_purdue_level_traffic import CrossPurdueLevelTrafficModule
from elevadr_modules.modules.unknown_rogue_devices import UnknownRogueDevicesModule
from elevadr_modules.modules.unexpected_high_risk_port import UnexpectedHighRiskPortModule
from elevadr_modules.modules.weird_protocol_violations import WeirdProtocolViolationsModule
from elevadr_modules.modules.unusual_outbound_data_volume import UnusualOutboundDataVolumeModule
from elevadr_modules.modules.smb_signing_ntlmv1 import SmbSigningNtlmv1Module
from elevadr_modules.modules.smb_admin_share_access import SmbAdminShareAccessModule
from elevadr_modules.modules.kerberos_asrep_roastable import KerberosAsrepRoastableAccountsModule
from elevadr_modules.modules.ldap_cleartext_anonymous_cross_segment import LdapCleartextAnonymousCrossSegmentModule
from elevadr_modules.modules.name_resolution_poisoning_signals import NameResolutionPoisoningSignalsModule
from elevadr_modules.modules.rdp_nla_disabled import RdpNlaDisabledModule
from elevadr_modules.modules.upnp_ssdp_igd_port_mapping import UpnpSsdpIgdPortMappingModule
from elevadr_modules.modules.socks_open_proxy_behavior import SocksOpenProxyBehaviorModule
from elevadr_modules.modules.tls_sni_certificate_reuse import TlsSniCertificateReuseModule
from elevadr_modules.modules.ja3_fingerprint_outliers import Ja3FingerprintOutliersModule
from elevadr_modules.modules.http_user_agent_anomalies import HttpUserAgentAnomaliesModule
from elevadr_modules.modules.large_outbound_http_uploads import LargeOutboundHttpUploadsModule
from elevadr_modules.modules.icmp_data_channel import IcmpDataChannelModule
from elevadr_modules.modules.quic_ot_segments import QuicOtSegmentsModule
from elevadr_modules.modules.ics_write_operations import IcsWriteOperationsModule
from elevadr_modules.modules.enip_cip_write_session_abuses import EnipCipWriteSessionAbusesModule
from elevadr_modules.modules.bacnet_discovery_anomalies import BacnetDiscoveryAnomaliesModule
from elevadr_modules.modules.s7comm_unauthorized_write_stop import S7commUnauthorizedWriteStopModule
from elevadr_modules.modules.rogue_dhcp_static_ot import RogueDhcpStaticOtModule
from elevadr_modules.modules.ntp_internet_multi_dest_ot import NtpInternetMultiDestOtModule
from elevadr_modules.modules.vlan_tag_mismatch_double_tag import VlanTagMismatchDoubleTagModule
from elevadr_modules.modules.high_fan_in_out import HighFanInOutModule
from elevadr_modules.modules.file_extraction_sensitive_types import FileExtractionSensitiveTypesModule
from elevadr_modules.modules.engineering_tools_cleartext import EngineeringToolsCleartextModule
from elevadr_modules.modules.new_service_emergence_ot import NewServiceEmergenceOtModule
from elevadr_modules.modules.ot_management_certificate_risk import OtManagementCertificateRiskModule
from elevadr_modules.modules.excessive_broadcast_multicast_ot import ExcessiveBroadcastMulticastOtModule
from elevadr_modules.modules.niagara_fox_detected import NiagaraFoxDetectedModule
from elevadr_modules.modules.iccp_tase2_detected import IccpTase2DetectedModule
from elevadr_modules.modules.codesys_runtime_exposure import CodesysRuntimeExposureModule
from elevadr_modules.modules.database_service_exposed import DatabaseServiceExposedModule
from elevadr_modules.modules.remote_access_tool_exposure import RemoteAccessToolExposureModule
from elevadr_modules.modules.netbios_smbv1_exposure import NetbiosSmbv1ExposureModule
from elevadr_modules.modules.internet_exposed_ics import InternetExposedIcsModule
from elevadr_modules.modules.ipv6_traffic_ot import Ipv6TrafficOtModule
from elevadr_modules.modules.public_to_public_traffic import PublicToPublicTrafficModule
from elevadr_modules.modules.deprecated_vpn_protocol import DeprecatedVpnProtocolModule
from elevadr_modules.modules.irc_traffic_detected import IrcTrafficDetectedModule
from elevadr_modules.modules.control_system_enterprise_non_dmz import ControlSystemEnterpriseNonDmzModule
from elevadr_modules.modules.ot_external_dns_resolver import OtExternalDnsResolverModule
from elevadr_modules.modules.ot_outbound_internet_any_protocol import OtOutboundInternetAnyProtocolModule
from elevadr_modules.modules.plc_program_logic_firmware_update import PlcProgramLogicFirmwareUpdateModule
from elevadr_modules.modules.ot_asset_gone_silent import OtAssetGoneSilentModule
from elevadr_modules.modules.new_ot_conversation_pair import NewOtConversationPairModule
from elevadr_modules.modules.ics_protocol_error_spike import IcsProtocolErrorSpikeModule
from elevadr_modules.modules.snmp_write_ot_devices import SnmpWriteOtDevicesModule
from elevadr_modules.modules.arp_ip_mac_identity_change import ArpIpMacIdentityChangeModule
from elevadr_modules.modules.unexpected_dhcp_server import UnexpectedDhcpServerModule
from elevadr_modules.modules.ot_protocol_role_reversal import OtProtocolRoleReversalModule
from elevadr_modules.modules.plc_rtu_peer_change import PlcRtuPeerChangeModule
from elevadr_modules.modules.engineering_workstation_control_burst import EngineeringWorkstationControlBurstModule
from elevadr_modules.modules.dns_source_drift import DnsSourceDriftModule
from elevadr_modules.modules.ntp_source_drift import NtpSourceDriftModule
from elevadr_modules.modules.arp_l2_reconnaissance import ArpL2ReconnaissanceModule
from elevadr_modules.modules.unexpected_multicast_behavior import UnexpectedMulticastBehaviorModule
from elevadr_modules.modules.tcp_reset_abort_surge import TcpResetAbortSurgeModule
from elevadr_modules.modules.encrypted_session_fingerprint_change import EncryptedSessionFingerprintChangeModule
from elevadr_modules.modules.remote_access_session_anomaly import RemoteAccessSessionAnomalyModule
from elevadr_modules.modules.service_disappearance_replacement import ServiceDisappearanceReplacementModule
from elevadr_modules.modules.polling_cadence_disruption import PollingCadenceDisruptionModule
from elevadr_modules.modules.controller_communication_jitter import ControllerCommunicationJitterModule


MODULES: dict[str, AnalysisModule] = {
    CleartextCredentialsModule.metadata.id: CleartextCredentialsModule(),
    DeprecatedInsecureServicesProtocolsModule.metadata.id: DeprecatedInsecureServicesProtocolsModule(),
    WeakBrokenTlsSslModule.metadata.id: WeakBrokenTlsSslModule(),
    TlsCertificateAnomaliesModule.metadata.id: TlsCertificateAnomaliesModule(),
    BeaconingC2Module.metadata.id: BeaconingC2Module(),
    PortHostScanningModule.metadata.id: PortHostScanningModule(),
    BruteForceAuthenticationModule.metadata.id: BruteForceAuthenticationModule(),
    DnsTunnelingExfiltrationModule.metadata.id: DnsTunnelingExfiltrationModule(),
    OtProtocolExposureModule.metadata.id: OtProtocolExposureModule(),
    CrossPurdueLevelTrafficModule.metadata.id: CrossPurdueLevelTrafficModule(),
    UnknownRogueDevicesModule.metadata.id: UnknownRogueDevicesModule(),
    UnexpectedHighRiskPortModule.metadata.id: UnexpectedHighRiskPortModule(),
    WeirdProtocolViolationsModule.metadata.id: WeirdProtocolViolationsModule(),
    UnusualOutboundDataVolumeModule.metadata.id: UnusualOutboundDataVolumeModule(),
    SmbSigningNtlmv1Module.metadata.id: SmbSigningNtlmv1Module(),
    SmbAdminShareAccessModule.metadata.id: SmbAdminShareAccessModule(),
    KerberosAsrepRoastableAccountsModule.metadata.id: KerberosAsrepRoastableAccountsModule(),
    LdapCleartextAnonymousCrossSegmentModule.metadata.id: LdapCleartextAnonymousCrossSegmentModule(),
    NameResolutionPoisoningSignalsModule.metadata.id: NameResolutionPoisoningSignalsModule(),
    RdpNlaDisabledModule.metadata.id: RdpNlaDisabledModule(),
    UpnpSsdpIgdPortMappingModule.metadata.id: UpnpSsdpIgdPortMappingModule(),
    SocksOpenProxyBehaviorModule.metadata.id: SocksOpenProxyBehaviorModule(),
    TlsSniCertificateReuseModule.metadata.id: TlsSniCertificateReuseModule(),
    Ja3FingerprintOutliersModule.metadata.id: Ja3FingerprintOutliersModule(),
    HttpUserAgentAnomaliesModule.metadata.id: HttpUserAgentAnomaliesModule(),
    LargeOutboundHttpUploadsModule.metadata.id: LargeOutboundHttpUploadsModule(),
    IcmpDataChannelModule.metadata.id: IcmpDataChannelModule(),
    QuicOtSegmentsModule.metadata.id: QuicOtSegmentsModule(),
    IcsWriteOperationsModule.metadata.id: IcsWriteOperationsModule(),
    EnipCipWriteSessionAbusesModule.metadata.id: EnipCipWriteSessionAbusesModule(),
    BacnetDiscoveryAnomaliesModule.metadata.id: BacnetDiscoveryAnomaliesModule(),
    S7commUnauthorizedWriteStopModule.metadata.id: S7commUnauthorizedWriteStopModule(),
    RogueDhcpStaticOtModule.metadata.id: RogueDhcpStaticOtModule(),
    NtpInternetMultiDestOtModule.metadata.id: NtpInternetMultiDestOtModule(),
    VlanTagMismatchDoubleTagModule.metadata.id: VlanTagMismatchDoubleTagModule(),
    HighFanInOutModule.metadata.id: HighFanInOutModule(),
    FileExtractionSensitiveTypesModule.metadata.id: FileExtractionSensitiveTypesModule(),
    EngineeringToolsCleartextModule.metadata.id: EngineeringToolsCleartextModule(),
    NewServiceEmergenceOtModule.metadata.id: NewServiceEmergenceOtModule(),
    OtManagementCertificateRiskModule.metadata.id: OtManagementCertificateRiskModule(),
    ExcessiveBroadcastMulticastOtModule.metadata.id: ExcessiveBroadcastMulticastOtModule(),
    NiagaraFoxDetectedModule.metadata.id: NiagaraFoxDetectedModule(),
    IccpTase2DetectedModule.metadata.id: IccpTase2DetectedModule(),
    CodesysRuntimeExposureModule.metadata.id: CodesysRuntimeExposureModule(),
    InternetExposedIcsModule.metadata.id: InternetExposedIcsModule(),
    Ipv6TrafficOtModule.metadata.id: Ipv6TrafficOtModule(),
    PublicToPublicTrafficModule.metadata.id: PublicToPublicTrafficModule(),
    DatabaseServiceExposedModule.metadata.id: DatabaseServiceExposedModule(),
    RemoteAccessToolExposureModule.metadata.id: RemoteAccessToolExposureModule(),
    NetbiosSmbv1ExposureModule.metadata.id: NetbiosSmbv1ExposureModule(),
    DeprecatedVpnProtocolModule.metadata.id: DeprecatedVpnProtocolModule(),
    IrcTrafficDetectedModule.metadata.id: IrcTrafficDetectedModule(),
    ControlSystemEnterpriseNonDmzModule.metadata.id: ControlSystemEnterpriseNonDmzModule(),
    OtExternalDnsResolverModule.metadata.id: OtExternalDnsResolverModule(),
    OtOutboundInternetAnyProtocolModule.metadata.id: OtOutboundInternetAnyProtocolModule(),
    PlcProgramLogicFirmwareUpdateModule.metadata.id: PlcProgramLogicFirmwareUpdateModule(),
    OtAssetGoneSilentModule.metadata.id: OtAssetGoneSilentModule(),
    NewOtConversationPairModule.metadata.id: NewOtConversationPairModule(),
    IcsProtocolErrorSpikeModule.metadata.id: IcsProtocolErrorSpikeModule(),
    SnmpWriteOtDevicesModule.metadata.id: SnmpWriteOtDevicesModule(),
    ArpIpMacIdentityChangeModule.metadata.id: ArpIpMacIdentityChangeModule(),
    UnexpectedDhcpServerModule.metadata.id: UnexpectedDhcpServerModule(),
    OtProtocolRoleReversalModule.metadata.id: OtProtocolRoleReversalModule(),
    PlcRtuPeerChangeModule.metadata.id: PlcRtuPeerChangeModule(),
    EngineeringWorkstationControlBurstModule.metadata.id: EngineeringWorkstationControlBurstModule(),
    DnsSourceDriftModule.metadata.id: DnsSourceDriftModule(),
    NtpSourceDriftModule.metadata.id: NtpSourceDriftModule(),
    ArpL2ReconnaissanceModule.metadata.id: ArpL2ReconnaissanceModule(),
    UnexpectedMulticastBehaviorModule.metadata.id: UnexpectedMulticastBehaviorModule(),
    TcpResetAbortSurgeModule.metadata.id: TcpResetAbortSurgeModule(),
    EncryptedSessionFingerprintChangeModule.metadata.id: EncryptedSessionFingerprintChangeModule(),
    RemoteAccessSessionAnomalyModule.metadata.id: RemoteAccessSessionAnomalyModule(),
    ServiceDisappearanceReplacementModule.metadata.id: ServiceDisappearanceReplacementModule(),
    PollingCadenceDisruptionModule.metadata.id: PollingCadenceDisruptionModule(),
    ControllerCommunicationJitterModule.metadata.id: ControllerCommunicationJitterModule(),
}


def get_module(module_id: str) -> AnalysisModule:
    try:
        return MODULES[module_id]
    except KeyError as exc:
        available = ", ".join(sorted(MODULES)) or "(none)"
        raise KeyError(f"Unknown module '{module_id}'. Available: {available}") from exc


def list_modules() -> list[dict[str, object]]:
    items = []
    for module in MODULES.values():
        metadata = module.metadata
        item: dict[str, object] = {
            "id": metadata.id,
            "name": metadata.name,
            "description": metadata.description,
            "category": metadata.category,
            "required_logs": list(metadata.required_logs),
            "default_enabled": metadata.default_enabled,
        }
        if metadata.required_any_logs:
            item["required_any_logs"] = list(metadata.required_any_logs)
        items.append(item)
    return sorted(items, key=lambda item: str(item["id"]))
