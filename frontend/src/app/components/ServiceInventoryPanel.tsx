import React, { useMemo } from "react";
import Panel from "./Panel/Panel";
import SortableTable, { Column } from "./SortableTable/SortableTable";
import PivotValue from "./PivotValue/PivotValue";
import InfoTooltip from "./InfoTooltip/InfoTooltip";
import { InvestigationFilter, SelectedEntity } from "../types/Investigation";
import { OTService, ServiceCountPanel as ServiceCountPanelType } from "../types/Report";
import "./ServiceInventoryPanel.css";

interface ServiceInventoryPanelProps {
  serviceCount: ServiceCountPanelType;
  otServices: OTService[];
  implicatedCount: number;
  filters?: InvestigationFilter[];
  onFilter?: (filter: InvestigationFilter) => void;
  onSelect?: (entity: SelectedEntity) => void;
}

type ServiceClassification = "OT" | "IT" | "Other / Unclassified";

interface ServiceInventoryRow {
  name: string;
  port: number | null;
  connections: number;
  classification: ServiceClassification;
  description: string;
}

const normalize = (value: string): string => value.trim().toLowerCase();

const ServiceInventoryPanel: React.FC<ServiceInventoryPanelProps> = ({
  serviceCount,
  otServices,
  implicatedCount,
  filters = [],
  onFilter,
  onSelect,
}) => {
  const rows = useMemo(() => {
    const otByName = new Map(
      otServices.map((service) => [normalize(service["service.name"]), service]),
    );

    const knownRows: ServiceInventoryRow[] =
      serviceCount.service_connections_count.known_services.map((service) => {
        const otDefinition = otByName.get(normalize(service.name));
        return {
          name: service.name,
          port: service.port,
          connections: service.count,
          classification: otDefinition ? "OT" : "IT",
          description: otDefinition?.["service.description"] || "Identified general-purpose or enterprise network service.",
        };
      });

    const knownNames = new Set(knownRows.map((row) => normalize(row.name)));
    const supplementalOtRows: ServiceInventoryRow[] = otServices
      .filter((service) => !knownNames.has(normalize(service["service.name"])))
      .map((service) => ({
        name: service["service.name"],
        port: null,
        connections: 0,
        classification: "OT",
        description: service["service.description"] || "Industrial or control-system service.",
      }));

    const otherRows: ServiceInventoryRow[] = Object.entries(
      serviceCount.service_connections_count.unknown_services,
    ).map(([name, connections]) => ({
      name,
      port: null,
      connections,
      classification: "Other / Unclassified",
      description: "Observed service that could not be confidently classified as OT or IT.",
    }));

    return [...knownRows, ...supplementalOtRows, ...otherRows];
  }, [serviceCount, otServices]);

  const visibleRows = useMemo(
    () => rows.filter((row) => filters.every((filter) => {
      if (filter.key === "service") return row.name === filter.value;
      if (filter.key === "port") return String(row.port ?? "") === filter.value;
      return true;
    })),
    [rows, filters],
  );

  const groups: Array<{ key: ServiceClassification; description: string }> = [
    { key: "OT", description: "Industrial and control-system protocols identified by the report's OT service classification." },
    { key: "IT", description: "Identified enterprise and general-purpose network services not classified as OT." },
    { key: "Other / Unclassified", description: "Observed services that are not confidently classified as OT or IT." },
  ];

  const columns: Column<unknown, ServiceInventoryRow>[] = [
    {
      key: "name",
      label: "Service",
      sortable: true,
      render: (value) => {
        const name = String(value ?? "");
        return onFilter && name ? (
          <PivotValue filter={{ key: "service", value: name, label: "Service" }} filters={filters} onFilter={onFilter}>
            <strong>{name}</strong>
          </PivotValue>
        ) : <strong>{name}</strong>;
      },
    },
    {
      key: "port",
      label: "Port",
      sortable: true,
      align: "right",
      render: (value) => value != null && onFilter ? (
        <PivotValue filter={{ key: "port", value: String(value), label: "Port" }} filters={filters} onFilter={onFilter}>
          {String(value)}
        </PivotValue>
      ) : String(value ?? "—"),
    },
    { key: "connections", label: "Connections", sortable: true, align: "right" },
    { key: "description", label: "Description", sortable: true },
  ];

  const total = rows.length;
  const otCount = rows.filter((row) => row.classification === "OT").length;
  const itCount = rows.filter((row) => row.classification === "IT").length;
  const otherCount = rows.filter((row) => row.classification === "Other / Unclassified").length;

  return (
    <Panel
      id="service-inventory-panel"
      title={
        <div className="service-inventory-title">
          <span>Service Inventory</span>
          <InfoTooltip text="Observed services classified as OT, IT, or Other / Unclassified. Click a row to inspect service details; use the funnel beside a filterable value to filter the report." />
        </div>
      }
      isEmpty={total === 0}
    >
      <div className="service-inventory-summary" aria-label="Service classification summary">
        <div><span>Total</span><strong>{total}</strong></div>
        <div><span>OT</span><strong>{otCount}</strong></div>
        <div><span>IT</span><strong>{itCount}</strong></div>
        <div><span>Other / Unclassified</span><strong>{otherCount}</strong></div>
        <div className={implicatedCount > 0 ? "service-inventory-summary-warning" : undefined}><span>Implicated in Findings</span><strong>{implicatedCount}</strong></div>
      </div>

      <div className="service-inventory-groups">
        {groups.map((group) => {
          const groupRows = visibleRows.filter((row) => row.classification === group.key);
          const totalGroupRows = rows.filter((row) => row.classification === group.key).length;
          return (
            <section key={group.key} className="service-inventory-group" aria-labelledby={`service-inventory-${group.key.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}`}>
              <div className="service-inventory-group-heading">
                <div>
                  <h3 id={`service-inventory-${group.key.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}`}>{group.key} Services</h3>
                  <p>{group.description}</p>
                </div>
                <span>{totalGroupRows}</span>
              </div>
              <SortableTable
                columns={columns}
                data={groupRows}
                filterable={true}
                filterPlaceholder={`Search ${group.key.toLowerCase()} services...`}
                emptyMessage={`No ${group.key.toLowerCase()} services observed`}
                onRowClick={(row) => onSelect?.({ type: "service", id: row.name })}
              />
            </section>
          );
        })}
      </div>
    </Panel>
  );
};

export default ServiceInventoryPanel;
