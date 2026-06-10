import React from "react";
import SortableTable, { Column } from "../SortableTable/SortableTable";
import { Device, OTService, ServiceConnectionDetail } from "../../types/Report";

export const connectionDetailColumns: Column<
  unknown,
  ServiceConnectionDetail
>[] = [
  { key: "src_endpoint.ip", label: "Source IP", sortable: true },
  { key: "src_endpoint.subnet", label: "Src Subnet", sortable: true },
  { key: "src_device.manufacturer", label: "Src Manufacturer", sortable: true },
  {
    key: "src_endpoint.port",
    label: "Src Port",
    sortable: true,
    align: "right",
  },
  { key: "dst_endpoint.ip", label: "Destination IP", sortable: true },
  { key: "dst_endpoint.subnet", label: "Dst Subnet", sortable: true },
  { key: "dst_device.manufacturer", label: "Dst Manufacturer", sortable: true },
  {
    key: "dst_endpoint.port",
    label: "Dst Port",
    sortable: true,
    align: "right",
  },
  { key: "service.name", label: "Service", sortable: true },
  { key: "connection_info.protocol_name", label: "Protocol", sortable: true },
  { key: "connection_info.direction_name", label: "Direction", sortable: true },
  { key: "state", label: "State", sortable: true },
  {
    key: "success",
    label: "Success",
    sortable: true,
    render: (value) => (value ? "Yes" : "No"),
  },
];

const renderIpAddresses = (_value: unknown, row: Device) => {
  const ips = [...(row.ipv4_ips || []), ...(row.ipv6_ips || [])];
  return ips.length > 0 ? ips.join(", ") : "N/A";
};

const renderSubnets = (_value: unknown, row: Device) => {
  const subnets = [...(row.ipv4_subnets || []), ...(row.ipv6_subnets || [])];
  return subnets.length > 0 ? subnets.join(", ") : "N/A";
};

const renderServices = (services: string[] | null) =>
  services && services.length > 0 ? services.join(", ") : "N/A";

export const deviceDetailColumns: Column<unknown, Device>[] = [
  { key: "manufacturer", label: "Manufacturer", sortable: true },
  { key: "mac", label: "MAC", sortable: true },
  {
    key: "ip_addresses",
    label: "IP Address(es)",
    sortable: true,
    render: renderIpAddresses,
  },
  {
    key: "subnets",
    label: "Subnet(s)",
    sortable: true,
    render: renderSubnets,
  },
  {
    key: "incoming_services",
    label: "Incoming Services",
    sortable: true,
    render: (_value: unknown, row: Device) =>
      renderServices(row.incoming_services),
  },
  {
    key: "sent_services",
    label: "Sent Services",
    sortable: true,
    render: (_value: unknown, row: Device) => renderServices(row.sent_services),
  },
];

export interface OtServiceRow {
  name: string;
  description: string;
  informationCategories: string;
  riskCategories: string;
  riskCategoryList: string[];
}

export const buildOtServiceRows = (services: OTService[]) =>
  services.map((service) => ({
    name: service["service.name"],
    description: service["service.description"],
    informationCategories: service["service.information_categories"],
    riskCategories: service["service.risk_categories"],
    riskCategoryList: service["service.risk_categories"]
      ? service["service.risk_categories"]
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean)
      : [],
  }));

interface DrilldownTableProps<T = unknown, R extends object = object> {
  columns: Column<T, R>[];
  data: R[];
  filterPlaceholder: string;
  emptyMessage: string;
}

const DrilldownTable = <T = unknown, R extends object = object>({
  columns,
  data,
  filterPlaceholder,
  emptyMessage,
}: DrilldownTableProps<T, R>) => (
  <SortableTable
    columns={columns}
    data={data}
    filterable={true}
    filterPlaceholder={filterPlaceholder}
    emptyMessage={emptyMessage}
  />
);

export default DrilldownTable;
