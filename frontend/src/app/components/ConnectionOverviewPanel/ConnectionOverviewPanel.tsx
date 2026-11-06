import React, { useMemo } from "react";
import Panel from "../Panel/Panel";
import { ElevadrReport } from "../../types/Report";
import { deriveFindings } from "../FindingsPanel/FindingsPanel";
import "../ServicePanel/ServicePanel.css";

const ConnectionOverviewPanel: React.FC<{ report: ElevadrReport }> = ({
  report,
}) => {
  const uniqueConnections = useMemo(() => {
    const keys = new Set<string>();
    report.modules.connection_success_panel.connections.forEach(
      (connection) => {
        const src = connection["src_endpoint.ip"];
        const dst = connection["dst_endpoint.ip"];
        if (!src || !dst) return;
        const pair = [src, dst].sort().join("|");
        const protocol =
          connection["connection_info.protocol_name"] ||
          connection["service.name"] ||
          `port:${connection["dst_endpoint.port"] ?? "unknown"}`;
        keys.add(`${pair}|${protocol}`);
      },
    );
    return keys.size;
  }, [report]);
  const implicated = useMemo(() => {
    const keys = new Set<string>();
    deriveFindings(report).forEach((finding) => {
      if (!finding.ip || !finding.destination) return;
      keys.add(
        `${[finding.ip, finding.destination].sort().join("|")}|${finding.service || "unknown"}`,
      );
    });
    return keys.size;
  }, [report]);
  const subnets = useMemo(() => {
    const values = new Set<string>();
    report.modules.connection_success_panel.connections.forEach(
      (connection) => {
        if (connection["src_endpoint.subnet"])
          values.add(connection["src_endpoint.subnet"]!);
        if (connection["dst_endpoint.subnet"])
          values.add(connection["dst_endpoint.subnet"]!);
      },
    );
    [
      ...report.modules.ot_devices,
      ...report.modules.it_devices,
      ...report.modules.edge_devices,
    ].forEach((device) => {
      [
        ...(device.subnets || []),
        ...(device.ipv4_subnets || []),
        ...(device.ipv6_subnets || []),
      ].forEach((value) => value && values.add(value));
    });
    return values.size;
  }, [report]);
  const go = (id: string) =>
    document
      .getElementById(id)
      ?.scrollIntoView({ behavior: "smooth", block: "start" });
  return (
    <Panel
      id="connection-overview-panel"
      title="Connection Overview"
      isEmpty={uniqueConnections === 0}
    >
      <div className="data-grid">
        <button
          type="button"
          className="data-item linked data-item-button"
          onClick={() => go("network-topology")}
        >
          <span className="data-label">Connections</span>
          <span className="data-value">{uniqueConnections}</span>
        </button>
        <button
          type="button"
          className="data-item linked data-item-button"
          onClick={() => go("findings")}
        >
          <span className="data-label">Implicated In A Finding</span>
          <span
            className={`data-value${implicated ? " data-value-warning" : ""}`}
          >
            {implicated}
          </span>
        </button>
        <button
          type="button"
          className="data-item linked data-item-button"
          onClick={() => go("network-topology")}
        >
          <span className="data-label">Subnets</span>
          <span className="data-value">{subnets}</span>
        </button>
      </div>
      <p className="panel-count-disclaimer">
        A connection is one unique host-pair and protocol combination. Repeated
        flows between the same two hosts on the same protocol count once.
      </p>
    </Panel>
  );
};
export default ConnectionOverviewPanel;
