import React, { useMemo } from "react";
import Panel from "../Panel/Panel";
import SortableTable, { Column } from "../SortableTable/SortableTable";
import { Device } from "../../types/Report";
import InfoTooltip from "../InfoTooltip/InfoTooltip";
import PivotValue from "../PivotValue/PivotValue";
import { InvestigationFilter, SelectedEntity } from "../../types/Investigation";

interface DevicesPanelProps {
  otDevices: Device[];
  itDevices: Device[];
  edgeDevices: Device[];
  reportId: string;
  filters?: InvestigationFilter[];
  onFilter?: (filter: InvestigationFilter) => void;
  onSelect?: (entity: SelectedEntity) => void;
}

const buildDeviceColumns = (
  filters: InvestigationFilter[],
  onFilter?: (filter: InvestigationFilter) => void,
): Column<unknown, Device>[] => {
  const pivot = (value: string, filter: InvestigationFilter, strong = false) =>
    onFilter ? (
      <PivotValue filter={filter} filters={filters} onFilter={onFilter}>
        {strong ? <strong>{value}</strong> : value}
      </PivotValue>
    ) : (strong ? <strong>{value}</strong> : <>{value}</>);
  const pivots = (values: string[], key: InvestigationFilter["key"], label: string) => {
    const unique = values.filter((value, index, items) => value && items.indexOf(value) === index);
    if (!unique.length) return <>N/A</>;
    return (
      <span className="device-pivot-list">
        {unique.map((value, index) => (
          <React.Fragment key={`${key}-${value}`}>
            {index > 0 ? ", " : null}
            {pivot(value, { key, value, label })}
          </React.Fragment>
        ))}
      </span>
    );
  };

  return [
    {
      key: "manufacturer",
      label: (
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span>Manufacturer</span>
          <InfoTooltip text="The manufacturer of the device, identified via MAC address lookup." />
        </div>
      ),
      sortable: true,
      render: (value) => {
        const manufacturer = String(value ?? "Unknown");
        return pivot(manufacturer, { key: "manufacturer", value: manufacturer, label: "Manufacturer" }, true);
      },
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
      render: (_value: unknown, row: Device) => pivots([...(row.ip_addresses || []), ...(row.ipv4_ips || []), ...(row.ipv6_ips || [])], "ip", "Device"),
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
      render: (_value: unknown, row: Device) => pivots([...(row.subnets || []), ...(row.ipv4_subnets || []), ...(row.ipv6_subnets || [])], "subnet", "Subnet"),
    },
    {
      key: "incoming_services",
      label: (
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span>Incoming Services</span>
          <InfoTooltip text="Services that the device is receiving." />
        </div>
      ),
      sortable: true,
      render: (_value: unknown, row: Device) => pivots(row.incoming_services || [], "service", "Service"),
    },
    {
      key: "sent_services",
      label: (
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span>Sent Services</span>
          <InfoTooltip text="Services that the device is sending." />
        </div>
      ),
      sortable: true,
      render: (_value: unknown, row: Device) => pivots(row.sent_services || [], "service", "Service"),
    },
  ];
};

const DevicesPanel: React.FC<DevicesPanelProps> = ({
  otDevices,
  itDevices,
  edgeDevices,
  reportId: _reportId,
  filters = [],
  onFilter,
  onSelect,
}) => {
  const deviceColumns = buildDeviceColumns(filters, onFilter);

  const filterDevices = (items: Device[], className: string) => items.filter((device) => filters.every((filter) => {
    if (filter.key === "deviceClass") return className === filter.value;
    if (filter.key === "ip") return [...(device.ip_addresses || []), ...(device.ipv4_ips || []), ...(device.ipv6_ips || [])].includes(filter.value);
    if (filter.key === "service") return [...(device.incoming_services || []), ...(device.sent_services || [])].includes(filter.value);
    if (filter.key === "subnet") return [...(device.subnets || []), ...(device.ipv4_subnets || []), ...(device.ipv6_subnets || [])].includes(filter.value);
    if (filter.key === "manufacturer") return (device.manufacturer || "Unknown") === filter.value;
    return true;
  }));
  const visibleOtDevices = useMemo(() => filterDevices(otDevices, "OT"), [otDevices, filters]);
  const visibleItDevices = useMemo(() => filterDevices(itDevices, "IT"), [itDevices, filters]);
  const visibleEdgeDevices = useMemo(() => filterDevices(edgeDevices, "Network"), [edgeDevices, filters]);
  const primaryDeviceIp = (device: Device) => [...(device.ip_addresses || []), ...(device.ipv4_ips || []), ...(device.ipv6_ips || [])][0];

  const inspectDevice = (device: Device) => {
    const ip = primaryDeviceIp(device);
    if (!ip) return;
    onSelect?.({ type: "device", id: ip });
  };


  const isEmpty =
    otDevices.length === 0 &&
    itDevices.length === 0 &&
    edgeDevices.length === 0;
  return (
    <Panel
      id="devices-panel"
      title={
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span>Devices</span>
          <InfoTooltip text="A comprehensive list of all identified devices, categorized by type (OT, IT, Network). Click a device row to open full device details. Filterable values show a small funnel on hover; click the funnel to filter without opening the details drawer." />
        </div>
      }
      isEmpty={isEmpty}
    >
      <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
        <section
          id="ot-devices-panel"
          style={{ display: "flex", flexDirection: "column", gap: "8px" }}
        >
          <SortableTable
            columns={deviceColumns}
            data={visibleOtDevices}
            onRowClick={inspectDevice}
            filterable={true}
            filterHeader={
              <h3 className="section-subtitle">
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span>OT Devices</span>
                  <InfoTooltip text="Operational Technology (OT) devices detected on the network." />
                </div>
              </h3>
            }
            filterPlaceholder="Search OT devices..."
            emptyMessage="No Results"
          />
        </section>

        <section
          id="it-devices-panel"
          style={{ display: "flex", flexDirection: "column", gap: "8px" }}
        >
          <SortableTable
            columns={deviceColumns}
            data={visibleItDevices}
            onRowClick={inspectDevice}
            filterable={true}
            filterHeader={
              <h3 className="section-subtitle">
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span>IT Devices</span>
                  <InfoTooltip text="Information Technology (IT) devices detected on the network." />
                </div>
              </h3>
            }
            filterPlaceholder="Search IT devices..."
            emptyMessage="No Results"
          />
        </section>

        <section
          id="edge-devices-panel"
          style={{ display: "flex", flexDirection: "column", gap: "8px" }}
        >
          <SortableTable
            columns={deviceColumns}
            data={visibleEdgeDevices}
            onRowClick={inspectDevice}
            filterable={true}
            filterHeader={
              <h3 className="section-subtitle">
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span>Network Devices</span>
                  <InfoTooltip text="Network devices detected on the network, typically those communicating with external networks." />
                </div>
              </h3>
            }
            filterPlaceholder="Search Network devices..."
            emptyMessage="No Results"
          />
        </section>
      </div>




    </Panel>
  );
};

export default DevicesPanel;
