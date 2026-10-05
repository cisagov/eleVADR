import React, { useMemo } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ElevadrReport } from "../../types/Report";
import { InvestigationFilter, SelectedEntity } from "../../types/Investigation";
import { deriveFindings } from "../FindingsPanel/FindingsPanel";
import Panel from "../Panel/Panel";
import "./SecurityOverview.css";

interface SecurityOverviewProps {
  report: ElevadrReport;
  onFilter?: (filter: InvestigationFilter) => void;
  onSelect?: (entity: SelectedEntity) => void;
}

type SummaryIconKind = "devices" | "services" | "connections" | "findings";

const SummaryIcon: React.FC<{ kind: SummaryIconKind }> = ({ kind }) => {
  const paths: Record<SummaryIconKind, React.ReactNode> = {
    devices: <><rect x="4" y="5" width="16" height="11" rx="2"/><path d="M8 20h8"/><path d="M12 16v4"/></>,
    services: <><path d="M5 6h14"/><path d="M5 12h14"/><path d="M5 18h14"/><circle cx="8" cy="6" r="1.5"/><circle cx="16" cy="12" r="1.5"/><circle cx="11" cy="18" r="1.5"/></>,
    connections: <><path d="M4 7h12"/><path d="m13 4 3 3-3 3"/><path d="M20 17H8"/><path d="m11 14-3 3 3 3"/></>,
    findings: <><path d="M5 4h14v16H5z"/><path d="M8 8h8M8 12h5M8 16h6"/></>,
  };
  return <svg className="nav-icon" viewBox="0 0 24 24" aria-hidden="true">{paths[kind]}</svg>;
};

const SecurityOverview: React.FC<SecurityOverviewProps> = ({ report, onFilter, onSelect }) => {
  const { modules } = report;
  const findings = useMemo(() => deriveFindings(report), [report]);

  const serviceData = useMemo(
    () => [...modules.service_count_panel.service_connections_count.known_services]
      .filter((item) => item.count > 0)
      .sort((a, b) => b.count - a.count)
      .slice(0, 8)
      .map((item) => ({ name: item.name, connections: item.count })),
    [modules.service_count_panel.service_connections_count.known_services],
  );

  const useLogScale = useMemo(() => {
    if (serviceData.length < 2) return false;
    const values = serviceData.map((item) => item.connections).filter((value) => value > 0);
    return values.length > 1 && Math.max(...values) / Math.min(...values) >= 50;
  }, [serviceData]);

  const implicatedServices = useMemo(
    () => new Set(findings.map((finding) => finding.service).filter(Boolean)).size,
    [findings],
  );

  const implicatedDevices = useMemo(() => {
    const devices = new Set<string>();
    findings.forEach((finding) => {
      if (finding.ip) devices.add(finding.ip);
      if (finding.destination) devices.add(finding.destination);
    });
    return devices.size;
  }, [findings]);

  const implicatedConnections = useMemo(() => {
    const connections = new Set<string>();
    findings.forEach((finding) => {
      if (finding.ip && finding.destination) {
        const pair = [finding.ip, finding.destination].sort().join("|");
        connections.add(`${pair}|${finding.service || "unknown"}`);
      }
    });
    return connections.size;
  }, [findings]);

  const uniqueConnections = useMemo(() => {
    const keys = new Set<string>();
    modules.connection_success_panel.connections.forEach((connection) => {
      const src = connection["src_endpoint.ip"];
      const dst = connection["dst_endpoint.ip"];
      if (!src || !dst) return;
      const pair = [src, dst].sort().join("|");
      const protocol = connection["connection_info.protocol_name"] || connection["service.name"] || `port:${connection["dst_endpoint.port"] ?? "unknown"}`;
      keys.add(`${pair}|${protocol}`);
    });
    return keys.size;
  }, [modules.connection_success_panel.connections]);

  const subnetCount = useMemo(() => {
    const subnets = new Set<string>();
    modules.connection_success_panel.connections.forEach((connection) => {
      const srcSubnet = connection["src_endpoint.subnet"];
      const dstSubnet = connection["dst_endpoint.subnet"];
      if (srcSubnet) subnets.add(srcSubnet);
      if (dstSubnet) subnets.add(dstSubnet);
    });
    [...modules.ot_devices, ...modules.it_devices, ...modules.edge_devices].forEach((device) => {
      [...(device.subnets || []), ...(device.ipv4_subnets || []), ...(device.ipv6_subnets || [])].forEach((subnet) => {
        if (subnet) subnets.add(subnet);
      });
    });
    return subnets.size;
  }, [modules]);

  const severityCounts = useMemo(() => findings.reduce<Record<string, number>>((counts, finding) => {
    counts[finding.severity] = (counts[finding.severity] || 0) + 1;
    return counts;
  }, {}), [findings]);

  const totalServices = modules.service_panel.num_known_services + modules.service_panel.num_unknown_services;
  const priorityFindings = (severityCounts.critical || 0) + (severityCounts.high || 0);

  const jumpTo = (id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const pivot = (section: string, filter?: InvestigationFilter, entity?: SelectedEntity) => {
    if (filter) onFilter?.(filter);
    if (entity) onSelect?.(entity);
    window.setTimeout(() => jumpTo(section), 0);
  };

  return (
    <div className="security-overview">
      <Panel
        id="summary-environment"
        title={
          <span className="summary-environment-title">
            <svg className="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
              <rect x="4" y="4" width="6" height="6" rx="1"/>
              <rect x="14" y="4" width="6" height="6" rx="1"/>
              <rect x="4" y="14" width="6" height="6" rx="1"/>
              <rect x="14" y="14" width="6" height="6" rx="1"/>
            </svg>
            <span>Environment Overview</span>
          </span>
        }
      >
        <section className="summary-unified" aria-label="Environment Overview">
          <div className="summary-unified-metrics" aria-label="Environment metrics">
            <article className="summary-unified-metric">
              <button type="button" className="summary-unified-main" onClick={() => pivot("devices")}>
                <span className="summary-unified-icon"><SummaryIcon kind="devices" /></span>
                <span className="summary-unified-copy"><span>Devices</span><strong>{modules.device_panel.hosts.toLocaleString()}</strong></span>
                <span className="summary-unified-chevron" aria-hidden="true">›</span>
              </button>
              <div className="summary-unified-breakdown">
                <button type="button" onClick={() => pivot("devices", { key: "deviceClass", value: "OT", label: "Class" })}>OT <strong>{modules.device_panel.ot_hosts.toLocaleString()}</strong></button>
                <button type="button" onClick={() => pivot("devices", { key: "deviceClass", value: "IT", label: "Class" })}>IT <strong>{modules.device_panel.it_hosts.toLocaleString()}</strong></button>
                <button type="button" onClick={() => pivot("devices", { key: "deviceClass", value: "Network", label: "Class" })}>Network <strong>{modules.device_panel.edge_hosts.toLocaleString()}</strong></button>
              </div>
              <button type="button" className={`summary-unified-impact${implicatedDevices > 0 ? " has-findings" : ""}`} onClick={() => pivot("findings")}>{implicatedDevices.toLocaleString()} implicated in findings</button>
            </article>

            <article className="summary-unified-metric">
              <button type="button" className="summary-unified-main" onClick={() => pivot("services")}>
                <span className="summary-unified-icon"><SummaryIcon kind="services" /></span>
                <span className="summary-unified-copy"><span>Services</span><strong>{totalServices.toLocaleString()}</strong></span>
                <span className="summary-unified-chevron" aria-hidden="true">›</span>
              </button>
              <div className="summary-unified-breakdown">
                <button type="button" onClick={() => pivot("services")}>Known <strong>{modules.service_panel.num_known_services.toLocaleString()}</strong></button>
                <button type="button" onClick={() => pivot("services")}>Unknown <strong>{modules.service_panel.num_unknown_services.toLocaleString()}</strong></button>
              </div>
              <button type="button" className={`summary-unified-impact${implicatedServices > 0 ? " has-findings" : ""}`} onClick={() => pivot("findings")}>{implicatedServices.toLocaleString()} implicated in findings</button>
            </article>

            <article className="summary-unified-metric">
              <button type="button" className="summary-unified-main" onClick={() => pivot("connections")}>
                <span className="summary-unified-icon"><SummaryIcon kind="connections" /></span>
                <span className="summary-unified-copy"><span>Connections</span><strong>{uniqueConnections.toLocaleString()}</strong></span>
                <span className="summary-unified-chevron" aria-hidden="true">›</span>
              </button>
              <div className="summary-unified-breakdown">
                <button type="button" onClick={() => pivot("connections")}>Subnets <strong>{subnetCount.toLocaleString()}</strong></button>
              </div>
              <button type="button" className={`summary-unified-impact${implicatedConnections > 0 ? " has-findings" : ""}`} onClick={() => pivot("findings")}>{implicatedConnections.toLocaleString()} implicated in findings</button>
            </article>

            <article className="summary-unified-metric summary-unified-metric-findings">
              <button type="button" className="summary-unified-main" onClick={() => pivot("findings")}>
                <span className="summary-unified-icon"><SummaryIcon kind="findings" /></span>
                <span className="summary-unified-copy"><span>Findings</span><strong>{findings.length.toLocaleString()}</strong></span>
                <span className="summary-unified-chevron" aria-hidden="true">›</span>
              </button>
              <div className="summary-unified-breakdown summary-unified-severity">
                <button type="button" onClick={() => pivot("findings", { key: "risk", value: "critical", label: "Risk" })}>Critical <strong>{severityCounts.critical || 0}</strong></button>
                <button type="button" onClick={() => pivot("findings", { key: "risk", value: "high", label: "Risk" })}>High <strong>{severityCounts.high || 0}</strong></button>
              </div>
              <button type="button" className={`summary-unified-impact${priorityFindings > 0 ? " has-findings" : ""}`} onClick={() => pivot("findings")}>{priorityFindings.toLocaleString()} high-priority findings</button>
            </article>
          </div>

          <div className="summary-unified-lower">
            <section id="summary-service-activity" className="summary-activity-compact" aria-label="Service Activity">
              <div className="summary-unified-subhead">
                <div><span>Service Activity</span><small>Top observed protocols</small></div>
                <div className="service-activity-actions">
                  {useLogScale && <span className="scale-indicator">Log scale</span>}
                  <button type="button" className="summary-panel-link" onClick={() => jumpTo("services")}>View Services</button>
                </div>
              </div>
              {serviceData.length > 0 ? (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={serviceData} layout="vertical" margin={{ top: 8, right: 28, left: 8, bottom: 4 }}>
                    <CartesianGrid stroke="#dfe1e2" horizontal={false} />
                    <XAxis type="number" axisLine={false} tickLine={false} allowDecimals={false} scale={useLogScale ? "log" : "auto"} domain={useLogScale ? [1, "auto"] : [0, "auto"]} />
                    <YAxis type="category" dataKey="name" width={82} axisLine={false} tickLine={false} tick={{ fontSize: 12 }} />
                    <Tooltip cursor={{ fill: "#f1f7fb" }} />
                    <Bar
                      dataKey="connections"
                      name="Observed flows"
                      fill="#005ea2"
                      cursor="pointer"
                      radius={[0, 2, 2, 0]}
                      onClick={(entry) => {
                        const service = String(entry.name);
                        pivot("services", undefined, { type: "service", id: service });
                      }}
                    />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="chart-empty">No known service activity was reported.</div>
              )}
            </section>

            <aside className="summary-takeaways" aria-label="Key takeaways">
              <div className="summary-unified-subhead"><div><span>Key Takeaways</span><small>At-a-glance capture context</small></div></div>
              <ul>
                <li><strong>{modules.device_panel.hosts.toLocaleString()}</strong> devices observed across OT, IT, and network classifications.</li>
                <li><strong>{totalServices.toLocaleString()}</strong> services observed; <strong>{modules.service_panel.num_unknown_services.toLocaleString()}</strong> are unknown.</li>
                <li><strong>{uniqueConnections.toLocaleString()}</strong> unique host-pair/protocol connections across <strong>{subnetCount.toLocaleString()}</strong> subnets.</li>
                <li><strong>{findings.length.toLocaleString()}</strong> findings identified, including <strong>{priorityFindings.toLocaleString()}</strong> critical/high findings.</li>
              </ul>
              <p>Device classes may overlap. Connection totals use unique host-pair and protocol combinations.</p>
            </aside>
          </div>
        </section>
      </Panel>
    </div>
  );
};

export default SecurityOverview;
