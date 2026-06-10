import React from "react";
import "./ExecutiveSummary.css";
import Panel from "../Panel/Panel";
import { ExecutiveSummary as ExecutiveSummaryType } from "../../types/Report";
import InfoTooltip from "../InfoTooltip/InfoTooltip";

interface ExecutiveSummaryProps {
  data: ExecutiveSummaryType;
}

const formatTitle = (key: string): string => {
  return key
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
};

// Helper function to strip HTML tags for tooltip text
const stripHtmlTags = (html: string): string => {
  const div = document.createElement("div");
  div.innerHTML = html;
  return div.textContent || div.innerText || "";
};

// Mapping of alert keys to target panel IDs
const alertTypeToPanelId: Record<string, string> = {
  ot_cross_segment_alert: "ot-cross-segment-panel",
  risky_services_alert: "service-risk-breakdown-panel",
  unknown_services_alert: "service-panel",
  suspicious_outbound_connections_alert:
    "suspicious-outbound-connections-panel",
  // Add new alert types and their corresponding panel IDs here if needed
};

const ExecutiveSummary: React.FC<ExecutiveSummaryProps> = ({ data }) => {
  const hasAlerts = Object.keys(data).length > 0;
  const isEmpty = !hasAlerts;

  const handleScrollToSection = (id: string) => {
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  return (
    <Panel
      title={
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span>Executive Summary</span>
          <InfoTooltip text="High-level security findings and alerts that require immediate attention." />
        </div>
      }
      highlight={true}
      isEmpty={isEmpty}
    >
      <div className="executive-summary-table">
        <table className="usa-table usa-table--borderless">
          <thead>
            <tr>
              <th scope="col">
                <div
                  style={{ display: "flex", alignItems: "center", gap: "4px" }}
                >
                  <span>Alert Type</span>
                  <InfoTooltip text="The category or type of security alert identified." />
                </div>
              </th>
              <th scope="col">
                <div
                  style={{ display: "flex", alignItems: "center", gap: "4px" }}
                >
                  <span>Details</span>
                  <InfoTooltip text="Specific information and context regarding the alert." />
                </div>
              </th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(data).map(([key, value]) => {
              const targetPanelId = alertTypeToPanelId[key];
              return (
                <tr key={key}>
                  <td className="alert-type">
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "4px",
                      }}
                    >
                      {targetPanelId ? (
                        <a
                          href={`#${targetPanelId}`}
                          onClick={(e) => {
                            e.preventDefault();
                            handleScrollToSection(targetPanelId);
                          }}
                          className="alert-link"
                        >
                          {formatTitle(key)}
                        </a>
                      ) : (
                        <span>{formatTitle(key)}</span>
                      )}
                      <InfoTooltip text={stripHtmlTags(value)} />
                    </div>
                  </td>
                  <td className="alert-content">
                    <div
                      dangerouslySetInnerHTML={{
                        __html: value.replace(/\n/g, "<br />"),
                      }}
                    />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Panel>
  );
};

export default ExecutiveSummary;
