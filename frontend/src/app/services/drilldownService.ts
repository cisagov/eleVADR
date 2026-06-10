import {
  ConnectionStateDrilldownResponse,
  CrossSegmentDrilldownResponse,
  FilteredConnectionsResponse,
  FilteredDevicesResponse,
  FilteredServicesResponse,
  ServiceDrilldownResponse,
  SuspiciousOutboundDrilldownResponse,
} from "../types/Report";

const BACKEND_HTTP = "http://localhost:8000";

async function parseError(response: Response): Promise<string> {
  const text = await response.text();
  return text || `Request failed with status ${response.status}`;
}

export async function fetchServiceDrilldown(
  reportId: string,
  serviceName: string,
  limit = 500,
): Promise<ServiceDrilldownResponse> {
  const response = await fetch(
    `${BACKEND_HTTP}/reports/${encodeURIComponent(reportId)}/drilldown/service/${encodeURIComponent(serviceName)}?limit=${limit}`,
  );

  if (!response.ok) {
    throw new Error(await parseError(response));
  }

  return (await response.json()) as ServiceDrilldownResponse;
}

export async function fetchConnectionStateDrilldown(
  reportId: string,
  state: string,
  limit = 500,
): Promise<ConnectionStateDrilldownResponse> {
  const response = await fetch(
    `${BACKEND_HTTP}/reports/${encodeURIComponent(reportId)}/drilldown/connection-state/${encodeURIComponent(state)}?limit=${limit}`,
  );

  if (!response.ok) {
    throw new Error(await parseError(response));
  }

  return (await response.json()) as ConnectionStateDrilldownResponse;
}

export async function fetchSuspiciousOutboundDrilldown(
  reportId: string,
  srcIp: string,
  dstIp: string,
  dstPort: number,
  serviceName: string,
  limit = 500,
): Promise<SuspiciousOutboundDrilldownResponse> {
  const params = new URLSearchParams({
    src_ip: srcIp,
    dst_ip: dstIp,
    dst_port: String(dstPort),
    service_name: serviceName,
    limit: String(limit),
  });

  const response = await fetch(
    `${BACKEND_HTTP}/reports/${encodeURIComponent(reportId)}/drilldown/suspicious-outbound?${params.toString()}`,
  );

  if (!response.ok) {
    throw new Error(await parseError(response));
  }

  return (await response.json()) as SuspiciousOutboundDrilldownResponse;
}

export async function fetchCrossSegmentDrilldown(
  reportId: string,
  srcSubnet: string,
  dstSubnet: string,
  limit = 500,
): Promise<CrossSegmentDrilldownResponse> {
  const params = new URLSearchParams({
    src_subnet: srcSubnet,
    dst_subnet: dstSubnet,
    limit: String(limit),
  });

  const response = await fetch(
    `${BACKEND_HTTP}/reports/${encodeURIComponent(reportId)}/drilldown/cross-segment?${params.toString()}`,
  );

  if (!response.ok) {
    throw new Error(await parseError(response));
  }

  return (await response.json()) as CrossSegmentDrilldownResponse;
}

export async function fetchFilteredConnections(
  reportId: string,
  filters: Record<string, string | number | boolean | null | undefined>,
): Promise<FilteredConnectionsResponse> {
  const params = new URLSearchParams();

  Object.entries(filters).forEach(([key, value]) => {
    if (value !== null && value !== undefined && value !== "") {
      params.append(key, String(value));
    }
  });

  const response = await fetch(
    `${BACKEND_HTTP}/reports/${encodeURIComponent(reportId)}/connections?${params.toString()}`,
  );

  if (!response.ok) {
    throw new Error(await parseError(response));
  }

  return (await response.json()) as FilteredConnectionsResponse;
}

export async function fetchFilteredDevices(
  reportId: string,
  filters: Record<string, string | number | boolean | null | undefined>,
): Promise<FilteredDevicesResponse> {
  const params = new URLSearchParams();

  Object.entries(filters).forEach(([key, value]) => {
    if (value !== null && value !== undefined && value !== "") {
      params.append(key, String(value));
    }
  });

  const response = await fetch(
    `${BACKEND_HTTP}/reports/${encodeURIComponent(reportId)}/devices?${params.toString()}`,
  );

  if (!response.ok) {
    throw new Error(await parseError(response));
  }

  return (await response.json()) as FilteredDevicesResponse;
}

export async function fetchFilteredServices(
  reportId: string,
  filters: Record<string, string | number | boolean | null | undefined>,
): Promise<FilteredServicesResponse> {
  const params = new URLSearchParams();

  Object.entries(filters).forEach(([key, value]) => {
    if (value !== null && value !== undefined && value !== "") {
      params.append(key, String(value));
    }
  });

  const response = await fetch(
    `${BACKEND_HTTP}/reports/${encodeURIComponent(reportId)}/services?${params.toString()}`,
  );

  if (!response.ok) {
    throw new Error(await parseError(response));
  }

  return (await response.json()) as FilteredServicesResponse;
}
