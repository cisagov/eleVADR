import React from "react";
import "../ServicePanel/ServicePanel.css";
import Panel from "../Panel/Panel";
import { DevicePanel as DevicePanelType } from "../../types/Report";
import InfoTooltip from "../InfoTooltip/InfoTooltip";

interface DevicePanelProps {
  data: DevicePanelType;
}

const DevicePanel: React.FC<DevicePanelProps> = ({ data }) => {
  const handleLinkClick = (panelId: string) => {
    const panel = document.getElementById(panelId);
    if (panel) {
      panel.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  const isEmpty =
    data.hosts === 0 &&
    data.ot_hosts === 0 &&
    data.it_hosts === 0 &&
    data.edge_hosts === 0 &&
    data.ot_cross_segment === 0;

  return (
    <Panel
      id="device-panel" // Added ID for navigation
      title={
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span>Device Panel</span>
          <InfoTooltip text="Total network devices detected, OT assets identified, and devices communicating across network segments." />
        </div>
      }
      isEmpty={isEmpty}
    >
      <div className="data-grid">
        <div
          className="data-item linked"
          onClick={() => handleLinkClick("devices-panel")}
        >
          <span className="data-label">
            <InfoTooltip text="The total number of unique devices (hosts) identified on the network. Click to see all devices." />
            Total Hosts
          </span>
          <span className="data-value">{data.hosts}</span>
        </div>
        <div
          className="data-item linked"
          onClick={() => handleLinkClick("ot-devices-panel")}
        >
          <span className="data-label">
            <InfoTooltip text="The number of Operational Technology (OT) devices detected on the network. Click to see details." />
            OT Hosts
          </span>
          <span className="data-value">{data.ot_hosts}</span>
        </div>
        <div
          className="data-item linked"
          onClick={() => handleLinkClick("it-devices-panel")}
        >
          <span className="data-label">
            <InfoTooltip text="The number of non-OT, non-edge IT devices detected on the network. Click to see details." />
            IT Hosts
          </span>
          <span className="data-value">{data.it_hosts}</span>
        </div>
        <div
          className="data-item linked"
          onClick={() => handleLinkClick("edge-devices-panel")}
        >
          <span className="data-label">
            <InfoTooltip text="The number of edge devices detected on the network. Click to see details." />
            Edge Hosts
          </span>
          <span className="data-value">{data.edge_hosts}</span>
        </div>
        <div
          className="data-item linked"
          onClick={() => handleLinkClick("ot-cross-segment-panel")}
        >
          <span className="data-label">
            <InfoTooltip text="The number of OT devices communicating across different network segments, which may indicate potential security risks. Click to see details." />
            OT Cross-Segment
          </span>
          <span className="data-value data-value-warning">
            {data.ot_cross_segment}
          </span>
        </div>
      </div>
    </Panel>
  );
};

export default DevicePanel;
