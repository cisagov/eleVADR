import React from "react";
import "./ServiceCountPanel.css";
import Panel from "../Panel/Panel";
import SortableTable, { Column } from "../SortableTable/SortableTable";
import { ServiceCountPanel as ServiceCountPanelType } from "../../types/Report";
import InfoTooltip from "../InfoTooltip/InfoTooltip";
import PivotValue from "../PivotValue/PivotValue";
import { InvestigationFilter, SelectedEntity } from "../../types/Investigation";

interface ServiceCountPanelProps {
  data: ServiceCountPanelType;
  filters?: InvestigationFilter[];
  onFilter?: (filter: InvestigationFilter) => void;
  onSelect?: (entity: SelectedEntity) => void;
}

const ServiceCountPanel: React.FC<ServiceCountPanelProps> = ({
  data,
  filters = [],
  onFilter,
  onSelect,
}) => {
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

  const knownServiceColumns: Column[] = [
    {
      key: "service",
      label: "Service Name",
      sortable: true,
      render: (value) =>
        value && onFilter ? (
          <PivotValue
            filter={{ key: "service", value: String(value), label: "Service" }}
            filters={filters}
            onFilter={onFilter}
          >
            {String(value)}
          </PivotValue>
        ) : (
          String(value ?? "")
        ),
    },
    {
      key: "port",
      label: "Port",
      sortable: true,
      align: "right",
      render: (value) =>
        value != null && onFilter ? (
          <PivotValue
            filter={{ key: "port", value: String(value), label: "Port" }}
            filters={filters}
            onFilter={onFilter}
          >
            {String(value)}
          </PivotValue>
        ) : (
          String(value ?? "—")
        ),
    },
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
      render: (value) =>
        value && onFilter ? (
          <PivotValue
            filter={{ key: "service", value: String(value), label: "Service" }}
            filters={filters}
            onFilter={onFilter}
          >
            {String(value)}
          </PivotValue>
        ) : (
          String(value ?? "")
        ),
    },
    {
      key: "connections",
      label: "Connections",
      sortable: true,
      align: "right",
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
          <SortableTable
            columns={knownServiceColumns}
            data={knownServicesData}
            filterable={true}
            filterHeader={
              <h3 className="section-subtitle">
                Known Services
                <InfoTooltip text="Services that have been identified and categorized based on known protocols and ports." />
              </h3>
            }
            filterPlaceholder="Search known services..."
            emptyMessage="No Results"
            onRowClick={(row) =>
              onSelect?.({ type: "service", id: String(row.service) })
            }
          />
        </div>

        <div className="service-table-section">
          <SortableTable
            columns={unknownServiceColumns}
            data={unknownServicesData}
            filterable={true}
            filterHeader={
              <h3 className="section-subtitle">
                Unknown Services
                <InfoTooltip text="Services that could not be identified or categorized based on known protocols and ports." />
              </h3>
            }
            filterPlaceholder="Search unknown services..."
            emptyMessage="No Results"
            onRowClick={(row) =>
              onSelect?.({ type: "service", id: String(row.service) })
            }
          />
        </div>
      </div>
    </Panel>
  );
};

export default ServiceCountPanel;
