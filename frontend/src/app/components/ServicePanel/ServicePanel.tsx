import React from "react";
import "./ServicePanel.css";
import Panel from "../Panel/Panel";
import { ServicePanel as ServicePanelType } from "../../types/Report";
import InfoTooltip from "../InfoTooltip/InfoTooltip";

interface ServicePanelProps {
  data: ServicePanelType;
}

const ServicePanel: React.FC<ServicePanelProps> = ({ data }) => {
  const handleLinkClick = (panelId: string) => {
    const panel = document.getElementById(panelId);
    if (panel) {
      panel.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  const totalServices = data.num_known_services + data.num_unknown_services;
  const isEmpty = totalServices === 0;

  return (
    <Panel
      id="service-panel"
      title={
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span>Service Panel</span>
          <InfoTooltip text="Summary of network services detected including known, OT-specific, risky, and unknown services." />
        </div>
      }
      isEmpty={isEmpty}
    >
      <div className="data-grid">
        <div
          className="data-item linked"
          onClick={() => handleLinkClick("service-count-panel")}
        >
          <span className="data-label">
            <InfoTooltip text="The total number of unique services identified on the network. Click to see details." />
            Total Services
          </span>
          <span className="data-value data-value-total">{totalServices}</span>
        </div>
        <div
          className="data-item linked"
          onClick={() => handleLinkClick("service-count-panel")}
        >
          <span className="data-label">
            <InfoTooltip text="Services that are recognized and have well-defined characteristics. Click to see details." />
            Known Services
          </span>
          <span className="data-value">{data.num_known_services}</span>
        </div>
        <div
          className="data-item linked"
          onClick={() => handleLinkClick("ot-services-panel")}
        >
          <span className="data-label">
            <InfoTooltip text="Operational Technology (OT) services specific to industrial control systems. Click to see details." />
            OT Services
          </span>
          <span className="data-value">{data.num_ot_services}</span>
        </div>
        <div
          className="data-item linked"
          onClick={() => handleLinkClick("service-risk-breakdown-panel")}
        >
          <span className="data-label">
            <InfoTooltip text="Services associated with security risks. Click to see details." />
            Risky Services
          </span>
          <span className="data-value data-value-warning">
            {data.num_risky_services}
          </span>
        </div>
        <div
          className="data-item linked"
          onClick={() => handleLinkClick("service-count-panel")}
        >
          <span className="data-label">
            <InfoTooltip text="Services that could not be identified. Click to see details." />
            Unknown Services
          </span>
          <span className="data-value data-value-warning">
            {data.num_unknown_services}
          </span>
        </div>
      </div>
    </Panel>
  );
};

export default ServicePanel;
