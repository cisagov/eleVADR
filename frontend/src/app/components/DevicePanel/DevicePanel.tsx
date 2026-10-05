import React, { useMemo } from "react";
import "../ServicePanel/ServicePanel.css";
import Panel from "../Panel/Panel";
import { ElevadrReport } from "../../types/Report";
import InfoTooltip from "../InfoTooltip/InfoTooltip";
import { deriveFindings } from "../FindingsPanel/FindingsPanel";
import { InvestigationFilter } from "../../types/Investigation";

interface DevicePanelProps {
  report: ElevadrReport;
  onFilter?: (filter: InvestigationFilter) => void;
  footerAction?: React.ReactNode;
}

const DevicePanel: React.FC<DevicePanelProps> = ({ report, onFilter, footerAction }) => {
  const data = report.modules.device_panel;
  const implicated = useMemo(() => {
    const ids = new Set<string>();
    deriveFindings(report).forEach((finding) => {
      if (finding.ip) ids.add(finding.ip);
      if (finding.destination) ids.add(finding.destination);
    });
    return ids.size;
  }, [report]);

  const go = (panelId: string, filter?: InvestigationFilter) => {
    if (filter) onFilter?.(filter);
    window.setTimeout(() => document.getElementById(panelId)?.scrollIntoView({ behavior: "smooth", block: "start" }), 0);
  };

  const isEmpty = data.hosts === 0 && data.ot_hosts === 0 && data.it_hosts === 0 && data.edge_hosts === 0;
  return (
    <Panel id="device-panel" title={<div style={{ display: "flex", alignItems: "center", gap: "8px" }}><span>Device Overview</span><InfoTooltip text="High-level counts for observed devices. Device classes may overlap, so subset counts may not add to the total." /></div>} isEmpty={isEmpty}>
      <div className="data-grid">
        <DataItem label="Devices" value={data.hosts} onClick={() => go("devices-panel")} />
        <DataItem label="OT Devices" value={data.ot_hosts} onClick={() => go("devices-panel", { key: "deviceClass", value: "OT", label: "Class" })} />
        <DataItem label="IT Devices" value={data.it_hosts} onClick={() => go("devices-panel", { key: "deviceClass", value: "IT", label: "Class" })} />
        <DataItem label="Network Devices" value={data.edge_hosts} onClick={() => go("devices-panel", { key: "deviceClass", value: "Network", label: "Class" })} />
        <DataItem label="Implicated In A Finding" value={implicated} onClick={() => go("findings")} warning={implicated > 0} />
      </div>
      <div className="asset-inventory-meta-row">
        <p className="panel-count-disclaimer">Device classes can overlap (for example, a device may be both OT and Network). Subset counts therefore may not add to the total.</p>
        {footerAction && <div className="asset-inventory-footer-action">{footerAction}</div>}
      </div>
    </Panel>
  );
};

const DataItem: React.FC<{label:string;value:number;onClick:()=>void;warning?:boolean}> = ({label,value,onClick,warning=false}) => (
  <button type="button" className="data-item linked data-item-button" onClick={onClick}>
    <span className="data-label">{label}</span>
    <span className={`data-value${warning ? " data-value-warning" : ""}`}>{value}</span>
  </button>
);
export default DevicePanel;
