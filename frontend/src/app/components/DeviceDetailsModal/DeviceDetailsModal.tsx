import React, { useEffect, useMemo, useRef } from "react";
import { Device, ElevadrReport, ServiceConnectionDetail } from "../../types/Report";
import { InvestigationFilter } from "../../types/Investigation";
import { deriveFindings } from "../FindingsPanel/FindingsPanel";
import PivotValue from "../PivotValue/PivotValue";
import "./DeviceDetailsModal.css";

interface DeviceDetailsModalProps {
  report: ElevadrReport;
  deviceId: string;
  filters?: InvestigationFilter[];
  onClose: () => void;
  onFilter: (filter: InvestigationFilter) => void;
}

const unique = (values: Array<string | null | undefined>): string[] => [...new Set(values.filter((value): value is string => Boolean(value)))];
const deviceIps = (device?: Device): string[] => device ? unique([...(device.ip_addresses || []), ...(device.ipv4_ips || []), ...(device.ipv6_ips || [])]) : [];
const deviceSubnets = (device?: Device): string[] => device ? unique([...(device.subnets || []), ...(device.ipv4_subnets || []), ...(device.ipv6_subnets || [])]) : [];

const DeviceDetailsModal: React.FC<DeviceDetailsModalProps> = ({ report, deviceId, filters = [], onClose, onFilter }) => {
  const closeRef = useRef<HTMLButtonElement>(null);
  const allDevices = useMemo(() => [...report.modules.ot_devices, ...report.modules.it_devices, ...report.modules.edge_devices], [report]);
  const device = useMemo(() => allDevices.find((candidate) => deviceIps(candidate).includes(deviceId)), [allDevices, deviceId]);
  const allFindings = useMemo(() => deriveFindings(report), [report]);
  const connections = useMemo(() => report.modules.connection_success_panel.connections.filter((row) => row["src_endpoint.ip"] === deviceId || row["dst_endpoint.ip"] === deviceId), [report, deviceId]);
  const inboundConnections = useMemo(() => connections.filter((row) => row["dst_endpoint.ip"] === deviceId), [connections, deviceId]);
  const outboundConnections = useMemo(() => connections.filter((row) => row["src_endpoint.ip"] === deviceId), [connections, deviceId]);
  const findings = useMemo(() => allFindings.filter((finding) => finding.ip === deviceId || finding.destination === deviceId), [allFindings, deviceId]);
  const suspiciousOutbound = useMemo(() => report.modules.suspicious_outbound_connections_panel.filter((row) => row["src_endpoint.ip"] === deviceId || row["dst_endpoint.ip"] === deviceId), [report, deviceId]);
  const deviceClasses = useMemo(() => {
    const classes: string[] = [];
    if (report.modules.ot_devices.some((candidate) => deviceIps(candidate).includes(deviceId))) classes.push("OT");
    if (report.modules.it_devices.some((candidate) => deviceIps(candidate).includes(deviceId))) classes.push("IT");
    if (report.modules.edge_devices.some((candidate) => deviceIps(candidate).includes(deviceId))) classes.push("Network");
    return classes;
  }, [report, deviceId]);
  const observedMacs = useMemo(() => unique([
    device?.mac,
    ...connections.flatMap((row) => row["src_endpoint.ip"] === deviceId ? [row["src_device.mac"]] : row["dst_endpoint.ip"] === deviceId ? [row["dst_device.mac"]] : []),
  ]), [device, connections, deviceId]);
  const observedManufacturers = useMemo(() => unique([
    device?.manufacturer,
    ...connections.flatMap((row) => row["src_endpoint.ip"] === deviceId ? [row["src_device.manufacturer"]] : row["dst_endpoint.ip"] === deviceId ? [row["dst_device.manufacturer"]] : []),
  ]), [device, connections, deviceId]);
  const peers = useMemo(() => unique(connections.map((row) => row["src_endpoint.ip"] === deviceId ? row["dst_endpoint.ip"] : row["src_endpoint.ip"])), [connections, deviceId]);

  useEffect(() => {
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    closeRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [onClose]);

  const ips = deviceIps(device);
  const subnets = deviceSubnets(device);
  const incomingServices = unique(device?.incoming_services || []);
  const outgoingServices = unique(device?.sent_services || []);

  return (
    <div className="device-details-backdrop" role="presentation" onMouseDown={(event) => { if (event.currentTarget === event.target) onClose(); }}>
      <section className="device-details-modal" role="dialog" aria-modal="true" aria-labelledby="device-details-title">
        <header className="device-details-header">
          <div>
            <p>Device details</p>
            <h2 id="device-details-title">{deviceId}</h2>
            <span>{observedManufacturers[0] || "Manufacturer not identified"}</span>
          </div>
          <button ref={closeRef} type="button" onClick={onClose} aria-label="Close device details">×</button>
        </header>

        <div className="device-details-body">
          <div className="device-details-stats" aria-label="Device summary">
            <div><span>Observed flows</span><strong>{connections.length}</strong></div>
            <div><span>Inbound</span><strong>{inboundConnections.length}</strong></div>
            <div><span>Outbound</span><strong>{outboundConnections.length}</strong></div>
            <div><span>Connected peers</span><strong>{peers.length}</strong></div>
            <div><span>Findings</span><strong>{findings.length}</strong></div>
            <div><span>Services</span><strong>{unique([...incomingServices, ...outgoingServices]).length}</strong></div>
          </div>

          <DetailSection title="Identity and network">
            <DetailGrid>
              <DetailValue label="Manufacturer" value={observedManufacturers.length ? observedManufacturers.join(", ") : "—"} />
              <DetailValue label="MAC address(es)" value={observedMacs.length ? observedMacs.join(", ") : "—"} />
              <DetailValue label="Device class" value={deviceClasses.length ? deviceClasses.join(", ") : "Unknown"} />
              <DetailValue label="IP address(es)">
                <PivotList values={ips.length ? ips : [deviceId]} label="Device" filterKey="ip" filters={filters} onFilter={onFilter} />
              </DetailValue>
              <DetailValue label="Subnet(s)">
                {subnets.length ? <PivotList values={subnets} label="Subnet" filterKey="subnet" filters={filters} onFilter={onFilter} /> : "—"}
              </DetailValue>
            </DetailGrid>
          </DetailSection>

          <DetailSection title="Observed services">
            <div className="device-details-service-grid">
              <div><h4>Incoming services</h4>{incomingServices.length ? <PivotList values={incomingServices} label="Service" filterKey="service" filters={filters} onFilter={onFilter} /> : <p>None identified.</p>}</div>
              <div><h4>Sent services</h4>{outgoingServices.length ? <PivotList values={outgoingServices} label="Service" filterKey="service" filters={filters} onFilter={onFilter} /> : <p>None identified.</p>}</div>
            </div>
          </DetailSection>

          <DetailSection title={`Connections (${connections.length})`}>
            <DeviceConnectionTable rows={connections} deviceId={deviceId} filters={filters} onFilter={onFilter} />
          </DetailSection>

          <DetailSection title={`Associated findings (${findings.length})`}>
            {findings.length ? (
              <div className="device-details-findings">
                {findings.map((finding) => (
                  <article key={finding.id}>
                    <div><span className={`device-finding-severity severity-${finding.severity}`}>{finding.severity}</span><strong>{finding.title}</strong></div>
                    <p>{finding.summary}</p>
                    <small>{finding.moduleId ? `Module: ${finding.moduleId}` : "Report-derived finding"}</small>
                  </article>
                ))}
              </div>
            ) : <p className="device-details-empty">No findings in this report are directly associated with this device.</p>}
          </DetailSection>

          {suspiciousOutbound.length > 0 && (
            <DetailSection title="Suspicious outbound observations">
              <div className="device-details-suspicious">
                {suspiciousOutbound.map((row, index) => (
                  <div key={`${row["src_endpoint.ip"]}-${row["dst_endpoint.ip"]}-${row["dst_endpoint.port"]}-${index}`}>
                    <span><PivotValue filter={{ key: "ip", value: row["dst_endpoint.ip"], label: "Device" }} filters={filters} onFilter={onFilter}>{row["dst_endpoint.ip"]}</PivotValue>:{row["dst_endpoint.port"]}</span>
                    <strong>{row["service.name"] || "Unknown service"} · {row.count}</strong>
                  </div>
                ))}
              </div>
            </DetailSection>
          )}
        </div>

        <footer className="device-details-footer">
          <button type="button" className="usa-button" onClick={onClose}>Close</button>
        </footer>
      </section>
    </div>
  );
};

const DetailSection: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => <section className="device-details-section"><h3>{title}</h3>{children}</section>;
const DetailGrid: React.FC<{ children: React.ReactNode }> = ({ children }) => <div className="device-details-grid">{children}</div>;
const DetailValue: React.FC<{ label: string; value?: React.ReactNode; children?: React.ReactNode }> = ({ label, value, children }) => <div><span>{label}</span><strong>{children ?? value ?? "—"}</strong></div>;

const PivotList: React.FC<{ values: string[]; label: string; filterKey: InvestigationFilter["key"]; filters: InvestigationFilter[]; onFilter: (filter: InvestigationFilter) => void }> = ({ values, label, filterKey, filters, onFilter }) => (
  <div className="device-details-pivots">
    {values.map((value) => <PivotValue key={value} filter={{ key: filterKey, value, label }} filters={filters} onFilter={onFilter}>{value}</PivotValue>)}
  </div>
);

const DeviceConnectionTable: React.FC<{ rows: ServiceConnectionDetail[]; deviceId: string; filters: InvestigationFilter[]; onFilter: (filter: InvestigationFilter) => void }> = ({ rows, deviceId, filters, onFilter }) => {
  if (!rows.length) return <p className="device-details-empty">No flow-level connection records are available for this device.</p>;
  return (
    <div className="device-connection-table-wrap">
      <table className="device-connection-table">
        <thead><tr><th>Direction</th><th>Peer</th><th>Service</th><th>Port</th><th>Protocol</th><th>State</th><th>Result</th></tr></thead>
        <tbody>{rows.map((row, index) => {
          const outbound = row["src_endpoint.ip"] === deviceId;
          const peer = outbound ? row["dst_endpoint.ip"] : row["src_endpoint.ip"];
          const port = outbound ? row["dst_endpoint.port"] : row["src_endpoint.port"];
          return <tr key={`${row["src_endpoint.ip"]}-${row["dst_endpoint.ip"]}-${row["src_endpoint.port"]}-${row["dst_endpoint.port"]}-${index}`}>
            <td><span className={`connection-direction ${outbound ? "outbound" : "inbound"}`}>{outbound ? "Outbound" : "Inbound"}</span></td>
            <td>{peer ? <PivotValue filter={{ key: "ip", value: peer, label: "Device" }} filters={filters} onFilter={onFilter}>{peer}</PivotValue> : "—"}</td>
            <td>{row["service.name"] ? <PivotValue filter={{ key: "service", value: row["service.name"]!, label: "Service" }} filters={filters} onFilter={onFilter}>{row["service.name"]}</PivotValue> : "—"}</td>
            <td>{port ?? "—"}</td><td>{row["connection_info.protocol_name"] || "—"}</td><td>{row.state || "—"}</td><td>{row.success ? "Successful" : "Unsuccessful"}</td>
          </tr>;
        })}</tbody>
      </table>
    </div>
  );
};

export default DeviceDetailsModal;
