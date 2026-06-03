import React from "react";
import Panel from "../Panel/Panel";
import SortableTable, { Column } from "../SortableTable/SortableTable";
import { Device } from "../../types/Report";
import InfoTooltip from "../InfoTooltip/InfoTooltip";

interface GenericDevicePanelProps {
  data?: Device[];
  title: string;
  deviceType: "IT" | "OT" | "Edge";
}

const GenericDevicePanel: React.FC<GenericDevicePanelProps> = ({
  data = [],
  title,
  deviceType,
}) => {
  const columns: Column<unknown, Device>[] = [
    {
      key: "manufacturer",
      label: (
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span>Manufacturer</span>
          <InfoTooltip text="The manufacturer of the device, identified via MAC address lookup." />
        </div>
      ),
      sortable: true,
    },
    {
      key: "ip_addresses",
      label: (
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span>IP Address(es)</span>
          <InfoTooltip text="The IP address(es) of the device." />
        </div>
      ),
      sortable: true,
      render: (_value: unknown, row: Device) => {
        const ips = [...(row.ipv4_ips || []), ...(row.ipv6_ips || [])];
        return ips.length > 0 ? ips.join(", ") : "N/A";
      },
    },
    {
      key: "subnets",
      label: (
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span>Subnet(s)</span>
          <InfoTooltip text="The subnet(s) the device belongs to." />
        </div>
      ),
      sortable: true,
      render: (_value: unknown, row: Device) => {
        const subnets = [
          ...(row.ipv4_subnets || []),
          ...(row.ipv6_subnets || []),
        ];
        return subnets.length > 0 ? subnets.join(", ") : "N/A";
      },
    },
    {
      key: "incoming_services",
      label: (
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span>Services</span>
          <InfoTooltip text="The services the device is using." />
        </div>
      ),
      sortable: true,
      render: (_value: unknown, row: Device) =>
        row.incoming_services ? row.incoming_services.join(", ") : "N/A",
    },
  ];

  const isEmpty = data.length === 0;

  return (
    <Panel
      id={`${deviceType.toLowerCase()}-devices-panel`}
      title={
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span>{title}</span>
          <InfoTooltip
            text={`A list of all identified ${deviceType} devices on the network.`}
          />
        </div>
      }
      isEmpty={isEmpty}
    >
      <SortableTable<unknown, Device>
        columns={columns}
        data={data}
        filterable={true}
        filterPlaceholder={`Search by IP or Manufacturer...`}
        emptyMessage={`No ${deviceType} devices detected`}
      />
    </Panel>
  );
};

export default GenericDevicePanel;
