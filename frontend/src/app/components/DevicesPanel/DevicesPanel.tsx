import React from "react";
import Panel from "../Panel/Panel";
import SortableTable, { Column } from "../SortableTable/SortableTable";
import { Device, ServiceConnectionDetail } from "../../types/Report";
import InfoTooltip from "../InfoTooltip/InfoTooltip";
import DetailModal from "../DetailModal/DetailModal";
import { usePivotDrilldown } from "../../hooks/usePivotDrilldown";
import {
  fetchFilteredConnections,
  fetchFilteredDevices,
} from "../../services/drilldownService";
import DrilldownTable, {
  connectionDetailColumns,
} from "../DrilldownTable/DrilldownTable";
import PivotFilterBar from "../PivotFilterBar/PivotFilterBar";

interface DevicesPanelProps {
  otDevices: Device[];
  itDevices: Device[];
  edgeDevices: Device[];
  reportId: string;
}

const renderIpAddresses = (_value: unknown, row: Device) => {
  const ips = [...(row.ipv4_ips || []), ...(row.ipv6_ips || [])];
  return ips.length > 0 ? ips.join(", ") : "N/A";
};

const buildDeviceColumns = (
  onManufacturerClick: (manufacturer: string) => void,
  onSubnetClick: (subnet: string) => void,
  onIncomingServiceClick: (service: string) => void,
  onSentServiceClick: (service: string) => void,
): Column<unknown, Device>[] => [
  {
    key: "manufacturer",
    label: (
      <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
        <span>Manufacturer</span>
        <InfoTooltip text="The manufacturer of the device, identified via MAC address lookup." />
      </div>
    ),
    sortable: true,
    clickable: true,
    onClick: (value) => {
      if (value) onManufacturerClick(String(value));
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "Unknown")}
      </button>
    ),
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
    render: renderIpAddresses,
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
      if (subnets.length === 0) return "N/A";
      return (
        <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
          {subnets.map((subnet) => (
            <button
              key={subnet}
              type="button"
              className="clickable-service-link clickable-cell-text"
              onClick={(event) => {
                event.stopPropagation();
                onSubnetClick(subnet);
              }}
            >
              {subnet}
            </button>
          ))}
        </div>
      );
    },
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
    render: (_value: unknown, row: Device) => {
      const services = row.incoming_services || [];
      if (services.length === 0) return "N/A";
      return (
        <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
          {services.map((service) => (
            <button
              key={service}
              type="button"
              className="clickable-service-link clickable-cell-text"
              onClick={(event) => {
                event.stopPropagation();
                onIncomingServiceClick(service);
              }}
            >
              {service}
            </button>
          ))}
        </div>
      );
    },
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
    render: (_value: unknown, row: Device) => {
      const services = row.sent_services || [];
      if (services.length === 0) return "N/A";
      return (
        <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
          {services.map((service) => (
            <button
              key={service}
              type="button"
              className="clickable-service-link clickable-cell-text"
              onClick={(event) => {
                event.stopPropagation();
                onSentServiceClick(service);
              }}
            >
              {service}
            </button>
          ))}
        </div>
      );
    },
  },
];

const buildConnectionPivotColumns = (
  onPivot: (
    filters: Record<string, string | number | boolean | null | undefined>,
  ) => void,
): Column<unknown, ServiceConnectionDetail>[] => [
  {
    ...connectionDetailColumns[0],
    clickable: true,
    onClick: (value) => {
      if (value) onPivot({ src_ip: String(value) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "Unknown")}
      </button>
    ),
  },
  {
    ...connectionDetailColumns[1],
    clickable: true,
    onClick: (value) => {
      if (value) onPivot({ src_subnet: String(value) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "Unknown")}
      </button>
    ),
  },
  {
    ...connectionDetailColumns[2],
    clickable: true,
    onClick: (_value, row: ServiceConnectionDetail) => {
      const manufacturer = row["src_device.manufacturer"];
      if (manufacturer) onPivot({ manufacturer: String(manufacturer) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "Unknown")}
      </button>
    ),
  },
  connectionDetailColumns[3],
  {
    ...connectionDetailColumns[4],
    clickable: true,
    onClick: (value) => {
      if (value) onPivot({ dst_ip: String(value) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "Unknown")}
      </button>
    ),
  },
  {
    ...connectionDetailColumns[5],
    clickable: true,
    onClick: (value) => {
      if (value) onPivot({ dst_subnet: String(value) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "Unknown")}
      </button>
    ),
  },
  {
    ...connectionDetailColumns[6],
    clickable: true,
    onClick: (_value, row: ServiceConnectionDetail) => {
      const manufacturer = row["dst_device.manufacturer"];
      if (manufacturer) onPivot({ manufacturer: String(manufacturer) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "Unknown")}
      </button>
    ),
  },
  connectionDetailColumns[7],
  {
    ...connectionDetailColumns[8],
    clickable: true,
    onClick: (value) => {
      if (value) onPivot({ service_name: String(value) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "Unknown")}
      </button>
    ),
  },
  connectionDetailColumns[9],
  {
    ...connectionDetailColumns[10],
    clickable: true,
    onClick: (value) => {
      if (value) onPivot({ direction: String(value) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "Unknown")}
      </button>
    ),
  },
  {
    ...connectionDetailColumns[11],
    clickable: true,
    onClick: (value) => {
      if (value) onPivot({ connection_state: String(value) });
    },
    render: (value) => (
      <button
        type="button"
        className="clickable-service-link clickable-cell-text"
      >
        {String(value ?? "Unknown")}
      </button>
    ),
  },
  connectionDetailColumns[12],
];

const DevicesPanel: React.FC<DevicesPanelProps> = ({
  otDevices,
  itDevices,
  edgeDevices,
  reportId,
}) => {
  const deviceDrilldown = usePivotDrilldown(
    (filters: Record<string, string | number | boolean | null | undefined>) =>
      fetchFilteredDevices(reportId, filters),
  );
  const connectionDrilldown = usePivotDrilldown(
    (filters: Record<string, string | number | boolean | null | undefined>) =>
      fetchFilteredConnections(reportId, filters),
  );

  const handleManufacturerClick = async (manufacturer: string) => {
    await deviceDrilldown.open({ manufacturer });
  };

  const handleSubnetClick = async (subnet: string) => {
    await connectionDrilldown.open({ subnet, limit: 500 });
  };

  const handleIncomingServiceClick = async (serviceName: string) => {
    await connectionDrilldown.open({ service_name: serviceName, limit: 500 });
  };

  const handleSentServiceClick = async (serviceName: string) => {
    await connectionDrilldown.open({ service_name: serviceName, limit: 500 });
  };

  const deviceColumns = buildDeviceColumns(
    handleManufacturerClick,
    handleSubnetClick,
    handleIncomingServiceClick,
    handleSentServiceClick,
  );

  const connectionColumns = buildConnectionPivotColumns((filters) => {
    void connectionDrilldown.pivot(filters);
  });

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
          <InfoTooltip text="A comprehensive list of all identified devices, categorized by type (OT, IT, Edge). Click manufacturers, subnets, or services to inspect related records and continue pivoting from the results." />
        </div>
      }
      isEmpty={isEmpty}
    >
      <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
        <section
          id="ot-devices-panel"
          style={{ display: "flex", flexDirection: "column", gap: "8px" }}
        >
          <h3 className="section-subtitle">
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span>OT Devices</span>
              <InfoTooltip text="Operational Technology (OT) devices detected on the network." />
            </div>
          </h3>
          <SortableTable
            columns={deviceColumns}
            data={otDevices}
            filterable={true}
            filterPlaceholder="Search OT devices..."
            emptyMessage="No Results"
          />
        </section>

        <section
          id="it-devices-panel"
          style={{ display: "flex", flexDirection: "column", gap: "8px" }}
        >
          <h3 className="section-subtitle">
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span>IT Devices</span>
              <InfoTooltip text="Information Technology (IT) devices detected on the network." />
            </div>
          </h3>
          <SortableTable
            columns={deviceColumns}
            data={itDevices}
            filterable={true}
            filterPlaceholder="Search IT devices..."
            emptyMessage="No Results"
          />
        </section>

        <section
          id="edge-devices-panel"
          style={{ display: "flex", flexDirection: "column", gap: "8px" }}
        >
          <h3 className="section-subtitle">
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span>Edge Devices</span>
              <InfoTooltip text="Edge devices detected on the network, typically those communicating with external networks." />
            </div>
          </h3>
          <SortableTable
            columns={deviceColumns}
            data={edgeDevices}
            filterable={true}
            filterPlaceholder="Search Edge devices..."
            emptyMessage="No Results"
          />
        </section>
      </div>

      <DetailModal
        isOpen={Boolean(deviceDrilldown.selectedFilters)}
        title="Filtered Devices"
        onClose={deviceDrilldown.close}
      >
        {deviceDrilldown.isLoading && <p>Loading matching devices...</p>}
        {deviceDrilldown.error && <p>{deviceDrilldown.error}</p>}
        {!deviceDrilldown.isLoading && !deviceDrilldown.error && (
          <>
            <PivotFilterBar
              filters={deviceDrilldown.selectedFilters}
              onRemoveFilter={(key) => {
                void deviceDrilldown.removeFilter(key);
              }}
            />
            <DrilldownTable
              columns={buildDeviceColumns(
                (manufacturer) => void deviceDrilldown.pivot({ manufacturer }),
                (subnet) =>
                  void connectionDrilldown.open({ subnet, limit: 500 }),
                (service) =>
                  void connectionDrilldown.open({
                    service_name: service,
                    limit: 500,
                  }),
                (service) =>
                  void connectionDrilldown.open({
                    service_name: service,
                    limit: 500,
                  }),
              )}
              data={deviceDrilldown.data?.devices || []}
              filterPlaceholder="Search matching devices..."
              emptyMessage="No matching devices found"
            />
          </>
        )}
      </DetailModal>

      <DetailModal
        isOpen={Boolean(connectionDrilldown.selectedFilters)}
        title="Filtered Connections"
        onClose={connectionDrilldown.close}
      >
        {connectionDrilldown.isLoading && (
          <p>Loading matching connections...</p>
        )}
        {connectionDrilldown.error && <p>{connectionDrilldown.error}</p>}
        {!connectionDrilldown.isLoading && !connectionDrilldown.error && (
          <>
            <PivotFilterBar
              filters={connectionDrilldown.selectedFilters}
              onRemoveFilter={(key) => {
                void connectionDrilldown.removeFilter(key);
              }}
            />
            <DrilldownTable
              columns={connectionColumns}
              data={connectionDrilldown.data?.connections || []}
              filterPlaceholder="Search matching connections..."
              emptyMessage="No matching connections found"
            />
          </>
        )}
      </DetailModal>
    </Panel>
  );
};

export default DevicesPanel;
