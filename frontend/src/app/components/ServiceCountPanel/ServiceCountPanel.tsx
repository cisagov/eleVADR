import React from "react";
import "./ServiceCountPanel.css";
import Panel from "../Panel/Panel";
import SortableTable, { Column } from "../SortableTable/SortableTable";
import {
  ElevadrReport,
  ServiceCountPanel as ServiceCountPanelType,
  ServiceConnectionDetail,
} from "../../types/Report";
import InfoTooltip from "../InfoTooltip/InfoTooltip";
import DetailModal from "../DetailModal/DetailModal";
import { useDrilldown } from "../../hooks/useDrilldown";
import { fetchServiceDrilldown } from "../../services/drilldownService";

interface ServiceCountPanelProps {
  data: ServiceCountPanelType;
  reportId: ElevadrReport["report_id"];
}

const ServiceCountPanel: React.FC<ServiceCountPanelProps> = ({
  data,
  reportId,
}) => {
  const drilldown = useDrilldown((serviceName: string) =>
    fetchServiceDrilldown(reportId, serviceName),
  );
  const knownServicesData = data.service_connections_count.known_services.map(
    (item) => ({
      service: item.name,
      port: item.port,
      connections: item.count,
    }),
  );

  const unknownServicesData = Object.entries(
    data.service_connections_count.unknown_services,
  ).map(([service, connections]) => ({ service, connections }));

  const handleServiceClick = async (serviceName: string) => {
    await drilldown.open(serviceName);
  };

  const closeModal = () => {
    drilldown.close();
  };

  const knownServiceColumns: Column[] = [
    {
      key: "service",
      label: "Service Name",
      sortable: true,
      clickable: true,
      onClick: (value) => handleServiceClick(String(value)),
      render: (value) => (
        <button type="button" className="clickable-service-link">
          {String(value ?? "")}
        </button>
      ),
    },
    { key: "port", label: "Port", sortable: true, align: "right" },
    {
      key: "connections",
      label: "Connections",
      sortable: true,
      align: "right",
    },
  ];

  const unknownServiceColumns: Column[] = [
    {
      key: "service",
      label: "Service Name",
      sortable: true,
      clickable: true,
      onClick: (value) => handleServiceClick(String(value)),
      render: (value) => (
        <button type="button" className="clickable-service-link">
          {String(value ?? "")}
        </button>
      ),
    },
    {
      key: "connections",
      label: "Connections",
      sortable: true,
      align: "right",
    },
  ];

  const detailColumns: Column[] = [
    { key: "src_endpoint.ip", label: "Source IP", sortable: true },
    {
      key: "src_endpoint.port",
      label: "Src Port",
      sortable: true,
      align: "right",
    },
    { key: "dst_endpoint.ip", label: "Destination IP", sortable: true },
    {
      key: "dst_endpoint.port",
      label: "Dst Port",
      sortable: true,
      align: "right",
    },
    { key: "connection_info.protocol_name", label: "Protocol", sortable: true },
    {
      key: "connection_info.direction_name",
      label: "Direction",
      sortable: true,
    },
    { key: "state", label: "State", sortable: true },
    { key: "history", label: "History", sortable: true },
    {
      key: "success",
      label: "Success",
      sortable: true,
      render: (value) => (value ? "Yes" : "No"),
    },
  ];

  const isEmpty = data.service_count === 0;

  return (
    <Panel
      id="service-count-panel"
      title={
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span>Service Count</span>
          <InfoTooltip text="Total unique services detected and their connection frequencies, separated into known and unknown services." />
        </div>
      }
      isEmpty={isEmpty}
    >
      <div className="service-count-header">
        <div className="total-services">
          <span className="total-label">Total Services:</span>
          <span className="total-value">{data.service_count}</span>
        </div>
      </div>

      <div className="service-tables-container">
        <div className="service-table-section">
          <h3 className="section-subtitle">
            Known Services
            <InfoTooltip text="Services that have been identified and categorized based on known protocols and ports." />
          </h3>
          <SortableTable
            columns={knownServiceColumns}
            data={knownServicesData}
            filterable={true}
            filterPlaceholder="Search known services..."
            emptyMessage="No Results"
          />
        </div>

        <div className="service-table-section">
          <h3 className="section-subtitle">
            Unknown Services
            <InfoTooltip text="Services that could not be identified or categorized based on known protocols and ports." />
          </h3>
          <SortableTable
            columns={unknownServiceColumns}
            data={unknownServicesData}
            filterable={true}
            filterPlaceholder="Search unknown services..."
            emptyMessage="No Results"
          />
        </div>
      </div>
      <DetailModal
        isOpen={Boolean(drilldown.selectedKey)}
        title={
          drilldown.selectedKey
            ? `Service Details: ${drilldown.selectedKey}`
            : "Service Details"
        }
        onClose={closeModal}
      >
        {drilldown.isLoading && <p>Loading service connections...</p>}
        {drilldown.error && <p>{drilldown.error}</p>}
        {!drilldown.isLoading && !drilldown.error && (
          <SortableTable
            columns={detailColumns}
            data={
              drilldown.data?.connections || ([] as ServiceConnectionDetail[])
            }
            filterable={true}
            filterPlaceholder="Search service connection details..."
            emptyMessage="No connections found for this service"
          />
        )}
      </DetailModal>
    </Panel>
  );
};

export default ServiceCountPanel;
