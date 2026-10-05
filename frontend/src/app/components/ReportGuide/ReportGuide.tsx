import React, { useMemo } from "react";
import { ElevadrReport } from "../../types/Report";
import "./ReportGuide.css";

interface Props {
  report: ElevadrReport;
  onGoTo: (section: string) => void;
  onAnalystMode: () => void;
}

const ReportGuide: React.FC<Props> = ({ report, onGoTo, onAnalystMode }) => {
  const summary = useMemo(() => {
    const risky = report.modules.service_panel.num_risky_services;
    const suspicious = report.modules.suspicious_outbound_connections_panel.length;
    const crossSegment = report.modules.device_panel.ot_cross_segment;
    const unsuccessful = report.modules.connection_success_panel.summary.unsuccessful_count;
    const attention = Number(risky > 0) + Number(suspicious > 0) + Number(crossSegment > 0) + Number(unsuccessful > 0);

    const parts: string[] = [];
    if (risky) parts.push(`${risky} risky service${risky === 1 ? "" : "s"}`);
    if (suspicious) parts.push(`${suspicious} suspicious outbound path${suspicious === 1 ? "" : "s"}`);
    if (crossSegment) parts.push(`${crossSegment} OT device${crossSegment === 1 ? "" : "s"} with cross-segment activity`);
    if (unsuccessful) parts.push(`${unsuccessful.toLocaleString()} unsuccessful connection${unsuccessful === 1 ? "" : "s"}`);

    return {
      attention,
      sentence: parts.length
        ? `This report highlights ${parts.slice(0, 3).join(", ")}${parts.length > 3 ? ", and additional connection issues" : ""}.`
        : "No elevated indicators were found in the headline report metrics. Review the evidence below to confirm expected network behavior.",
    };
  }, [report]);

  return (
    <section id="start" className="report-guide scroll-target" aria-labelledby="report-guide-title">
      <div className="report-guide-copy">
        <p className="report-guide-kicker">Start here</p>
        <h2 id="report-guide-title">{summary.attention ? `${summary.attention} areas deserve a closer look` : "Your report at a glance"}</h2>
        <p>{summary.sentence}</p>
        <span className="report-guide-note">eleVADR summarizes observed evidence; validate findings against your environment and approved communication patterns.</span>
      </div>
      <div className="report-guide-actions" aria-label="Recommended next steps">
        <button type="button" className="guide-action guide-action-primary" onClick={() => onGoTo("findings")}>
          <span className="guide-action-number">1</span><span><strong>Review findings</strong><small>See what may need attention</small></span>
        </button>
        <button type="button" className="guide-action" onClick={() => onGoTo("topology")}>
          <span className="guide-action-number">2</span><span><strong>Explore the network</strong><small>Understand devices and communication paths</small></span>
        </button>
        <button type="button" className="guide-action" onClick={() => { onAnalystMode(); window.setTimeout(() => onGoTo("assets"), 30); }}>
          <span className="guide-action-number">3</span><span><strong>Browse assets</strong><small>Inspect devices, services, and evidence</small></span>
        </button>
      </div>
    </section>
  );
};

export default ReportGuide;
