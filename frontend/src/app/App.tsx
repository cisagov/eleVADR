import React, { useState } from "react";
import "./App.css";
import { ElevadrReport } from "./types/Report";

import ExecutiveSummary from "./components/ExecutiveSummary/ExecutiveSummary";
import ServicePanel from "./components/ServicePanel/ServicePanel";
import DevicePanel from "./components/DevicePanel/DevicePanel";
import ServiceRiskBreakdownPanel from "./components/ServiceRiskBreakdownPanel/ServiceRiskBreakdownPanel";
import ServiceCountPanel from "./components/ServiceCountPanel/ServiceCountPanel";
import ConnectionSuccessPanel from "./components/ConnectionSuccessPanel/ConnectionSuccessPanel";
import SuspiciousOutboundConnectionsPanel from "./components/SuspiciousOutboundConnectionsPanel/SuspiciousOutboundConnectionsPanel";
import OTServices from "./components/OTServices/OTServices";
import OTCrossSegmentPanel from "./components/OTCrossSegmentPanel/OTCrossSegmentPanel";
import DevicesPanel from "./components/DevicesPanel/DevicesPanel";
import UploadForm from "./components/UploadForm/UploadForm";

const SUPPORTED_REPORT_MAJOR_VERSION = "2";

function isSupportedReportVersion(version?: string): boolean {
  if (!version || typeof version !== "string") return false;
  return version.split(".")[0] === SUPPORTED_REPORT_MAJOR_VERSION;
}

function App() {
  const [report, setReport] = useState<ElevadrReport | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const handleDownloadJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "elevadr-report.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  const hasSupportedReportVersion = report
    ? isSupportedReportVersion(report.report_version)
    : false;

  return (
    <div className="app-container">
      <div className="app-header">
        <h1>eleVADR Dashboard</h1>
        <p>OT Network Security Analysis</p>
      </div>

      <UploadForm
        onReportLoaded={setReport}
        report={report}
        onDownloadJson={handleDownloadJson}
        isAnalyzing={isAnalyzing}
        setIsAnalyzing={setIsAnalyzing}
      />

      {!report && !isAnalyzing && (
        <div className="status-container">
          <div className="loading-container">
            <p className="loading-text">Awaiting input...</p>
            <p className="error-details">
              Upload a PCAP above to generate an eleVADR report.
            </p>
          </div>
        </div>
      )}

      {report && !isAnalyzing && !hasSupportedReportVersion && (
        <div className="status-container">
          <div className="loading-container">
            <p className="loading-text">Unsupported report version</p>
            <p className="error-details">
              This report uses schema version "
              {report.report_version ?? "unknown"}", but this frontend only
              supports 2.x reports.
            </p>
          </div>
        </div>
      )}

      {report && !isAnalyzing && hasSupportedReportVersion && (
        <div className="panel-grid">
          <ExecutiveSummary data={report.executive_summary} />

          <div className="horizontal-panels">
            <ServicePanel data={report.modules.service_panel} />
            <DevicePanel data={report.modules.device_panel} />
          </div>

          <OTCrossSegmentPanel
            data={report.modules.ot_cross_segment_lines_panel}
            reportId={report.report_id}
          />

          <ServiceRiskBreakdownPanel
            data={report.modules.service_risk_breakdown_panel}
            reportId={report.report_id}
          />

          <ServiceCountPanel
            data={report.modules.service_count_panel}
            reportId={report.report_id}
          />

          <ConnectionSuccessPanel
            data={report.modules.connection_success_panel}
            reportId={report.report_id}
          />

          <SuspiciousOutboundConnectionsPanel
            data={report.modules.suspicious_outbound_connections_panel}
            reportId={report.report_id}
          />

          <DevicesPanel
            otDevices={report.modules.ot_devices}
            itDevices={report.modules.it_devices}
            edgeDevices={report.modules.edge_devices}
            reportId={report.report_id}
          />
          <OTServices
            data={report.modules.ot_services}
            reportId={report.report_id}
          />
        </div>
      )}
    </div>
  );
}

export default App;
