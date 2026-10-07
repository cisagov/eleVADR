import React, { useMemo } from "react";
import "./ServicePanel.css";
import Panel from "../Panel/Panel";
import { ElevadrReport } from "../../types/Report";
import InfoTooltip from "../InfoTooltip/InfoTooltip";
import { deriveFindings } from "../FindingsPanel/FindingsPanel";

interface ServicePanelProps {
  report: ElevadrReport;
}

const ServicePanel: React.FC<ServicePanelProps> = ({ report }) => {
  const data = report.modules.service_panel;
  const totalServices = data.num_known_services + data.num_unknown_services;
  const implicated = useMemo(
    () =>
      new Set(
        deriveFindings(report)
          .map((finding) => finding.service)
          .filter(Boolean),
      ).size,
    [report],
  );
  const otServices = data.num_ot_services;
  const itServices = Math.max(
    0,
    data.num_known_services - data.num_ot_services,
  );
  const otherServices = data.num_unknown_services;
  const go = (panelId: string) =>
    document
      .getElementById(panelId)
      ?.scrollIntoView({ behavior: "smooth", block: "start" });
  return (
    <Panel
      id="service-panel"
      title={
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span>Service Overview</span>
          <InfoTooltip text="High-level counts for observed services, including services implicated by the context of a security finding." />
        </div>
      }
      isEmpty={totalServices === 0}
    >
      <div className="data-grid">
        <DataItem
          label="Services"
          value={totalServices}
          onClick={() => go("service-inventory-panel")}
        />
        <DataItem
          label="OT Services"
          value={otServices}
          onClick={() => go("service-inventory-panel")}
        />
        <DataItem
          label="IT Services"
          value={itServices}
          onClick={() => go("service-inventory-panel")}
        />
        <DataItem
          label="Other / Unclassified"
          value={otherServices}
          onClick={() => go("service-inventory-panel")}
        />
        <DataItem
          label="Implicated In A Finding"
          value={implicated}
          onClick={() => go("findings")}
          warning={implicated > 0}
        />
      </div>
    </Panel>
  );
};
const DataItem: React.FC<{
  label: string;
  value: number;
  onClick: () => void;
  warning?: boolean;
}> = ({ label, value, onClick, warning = false }) => (
  <button
    type="button"
    className={`data-item linked data-item-button${warning ? " data-item-warning" : ""}`}
    onClick={onClick}
  >
    <span className="data-label">{label}</span>
    <span className={`data-value${warning ? " data-value-warning" : ""}`}>
      {value}
    </span>
  </button>
);
export default ServicePanel;
