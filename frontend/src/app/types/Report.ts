export interface ElevadrReport {
  report_version: string;
  report_id: string;
  executive_summary: ExecutiveSummary;
  modules: Modules;
  arch_insights: Record<string, unknown>;
}

export type ExecutiveSummary = Record<string, string>;

export interface OTActivityCrossSegmentLine {
  "src_endpoint.ip": string;
  "dst_endpoint.ip": string;
  "dst_endpoint.port": number;
  "service.name": string;
  count: number;
}

export interface OTSubnetPairCount {
  src_subnet: string;
  dst_subnet: string;
  count: number;
}

export interface OTSubnetCount {
  dst_subnet: string;
  count: number;
}

export interface OTOtDeviceCount {
  src_device_ip: string;
  count: number;
}

export interface OTcrossSegmentLinesPanel {
  lines: OTActivityCrossSegmentLine[];
  subnet_pair_counts: OTSubnetPairCount[];
  dst_subnet_counts: OTSubnetCount[];
  ot_device_counts: OTOtDeviceCount[];
}

export interface Modules {
  service_panel: ServicePanel;
  device_panel: DevicePanel;
  service_risk_breakdown_panel: ServiceRiskBreakdownPanel;
  service_count_panel: ServiceCountPanel;
  connection_success_panel: ConnectionSuccessPanel;
  suspicious_outbound_connections_panel: SuspiciousOutboundConnection[];
  ot_cross_segment_lines_panel: OTcrossSegmentLinesPanel;
  ot_devices: Device[];
  it_devices: Device[];
  edge_devices: Device[];
  ot_services: OTService[];
}

export interface ServicePanel {
  num_known_services: number;
  num_ot_services: number;
  num_risky_services: number;
  num_unknown_services: number;
}

export interface DevicePanel {
  hosts: number;
  ot_hosts: number;
  it_hosts: number;
  edge_hosts: number;
  ot_cross_segment: number;
}

export interface ServiceRiskBreakdownPanel {
  risk_category_counts: Record<string, number>;
  risk_category_services: Record<string, string[]>;
}

export interface KnownService {
  name: string;
  port: number;
  count: number;
}

export interface ServiceCountPanel {
  service_count: number;
  service_connections_count: {
    known_services: KnownService[];
    unknown_services: Record<string, number>;
  };
}

export interface ConnectionSuccessSummary {
  successful_count: number;
  unsuccessful_count: number;
  by_state: Record<string, number>;
}

export interface ConnectionSuccessLine {
  "src_endpoint.ip": string | null;
  "dst_endpoint.ip": string | null;
  "dst_endpoint.port": number | null;
  state: string | null;
  history?: string | null;
  success: boolean;
}

export interface ConnectionSuccessPanel {
  summary: ConnectionSuccessSummary;
  connections: ConnectionSuccessLine[];
}

export interface SuspiciousOutboundConnection {
  "src_endpoint.ip": string;
  "dst_endpoint.ip": string;
  "dst_endpoint.port": number;
  "service.name": string;
  count: number;
}

export interface OTService {
  "service.name": string;
  "service.description": string;
  "service.information_categories": string;
  "service.risk_categories": string;
}

export interface Device {
  manufacturer: string | null;
  mac?: string | null;
  ip_addresses: string[] | null;
  ipv4_ips?: string[] | null;
  ipv6_ips?: string[] | null;
  subnets: string[] | null;
  ipv4_subnets?: string[] | null;
  ipv6_subnets?: string[] | null;
  incoming_services: string[] | null;
  sent_services: string[] | null;
  is_ot?: boolean | null;
  is_edge?: boolean | null;
}

export interface ServiceConnectionDetail {
  "src_endpoint.ip": string | null;
  "src_endpoint.port": number | null;
  "src_endpoint.subnet"?: string | null;
  "dst_endpoint.ip": string | null;
  "dst_endpoint.port": number | null;
  "dst_endpoint.subnet"?: string | null;
  "service.name": string | null;
  "connection_info.protocol_name": string | null;
  "connection_info.direction_name": string | null;
  "src_device.mac"?: string | null;
  "src_device.manufacturer"?: string | null;
  "src_device.is_ot"?: boolean | null;
  "src_device.is_edge"?: boolean | null;
  "dst_device.mac"?: string | null;
  "dst_device.manufacturer"?: string | null;
  "dst_device.is_ot"?: boolean | null;
  "dst_device.is_edge"?: boolean | null;
  state: string | null;
  history?: string | null;
  success: boolean;
}

export interface ServiceDrilldownResponse {
  report_id: string;
  service_name: string;
  connections: ServiceConnectionDetail[];
}

export interface ConnectionStateDrilldownResponse {
  report_id: string;
  state: string;
  connections: ServiceConnectionDetail[];
}

export interface SuspiciousOutboundDrilldownResponse {
  report_id: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  service_name: string;
  connections: ServiceConnectionDetail[];
}

export interface CrossSegmentDrilldownResponse {
  report_id: string;
  src_subnet: string;
  dst_subnet: string;
  connections: ServiceConnectionDetail[];
}

export interface FilteredConnectionsResponse {
  report_id: string;
  filters: Record<string, string | number | boolean | null | undefined>;
  connections: ServiceConnectionDetail[];
}

export interface FilteredDevicesResponse {
  report_id: string;
  filters: Record<string, string | number | boolean | null | undefined>;
  devices: Device[];
}

export interface FilteredServicesResponse {
  report_id: string;
  filters: Record<string, string | number | boolean | null | undefined>;
  services: OTService[];
}
