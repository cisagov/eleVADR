import React, { useEffect, useMemo, useState } from "react";
import { Device, ElevadrReport, ServiceConnectionDetail } from "../../types/Report";
import { InvestigationFilter, SelectedEntity } from "../../types/Investigation";
import { deriveFindings } from "../FindingsPanel/FindingsPanel";
import PivotValue from "../PivotValue/PivotValue";
import "./EntityDrawer.css";

interface Props {
  report: ElevadrReport;
  entity: SelectedEntity | null;
  filters?: InvestigationFilter[];
  note?: string;
  overrides?: Record<string, string>;
  onSaveOverrides?: (value: Record<string, string>) => void;
  onResetOverrides?: () => void;
  onSaveNote: (value: string) => void;
  onDeleteNote: () => void;
  onClose: () => void;
  onFilter: (filter: InvestigationFilter) => void;
}

const unique = (values: Array<string | null | undefined>): string[] =>
  [...new Set(values.filter((value): value is string => Boolean(value)))];

const deviceIps = (device?: Device): string[] =>
  device
    ? unique([
        ...(device.ip_addresses || []),
        ...(device.ipv4_ips || []),
        ...(device.ipv6_ips || []),
      ])
    : [];

const deviceSubnets = (device?: Device): string[] =>
  device
    ? unique([
        ...(device.subnets || []),
        ...(device.ipv4_subnets || []),
        ...(device.ipv6_subnets || []),
      ])
    : [];

const EntityDrawer: React.FC<Props> = ({
  report,
  entity,
  filters = [],
  note = "",
  overrides = {},
  onSaveOverrides = () => undefined,
  onResetOverrides = () => undefined,
  onSaveNote,
  onDeleteNote,
  onClose,
  onFilter,
}) => {
  const [noteEditing, setNoteEditing] = useState(false);
  const [noteDraft, setNoteDraft] = useState(note);
  const [overrideEditing, setOverrideEditing] = useState(false);
  const [overrideDraft, setOverrideDraft] = useState<Record<string, string>>(overrides);

  useEffect(() => {
    setNoteDraft(note);
    setNoteEditing(false);
  }, [entity, note]);
  useEffect(() => {
    setOverrideDraft(overrides);
    setOverrideEditing(false);
  }, [entity, overrides]);
  useEffect(() => {
    if (!entity) return;
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [entity, onClose]);

  const allFindings = useMemo(() => deriveFindings(report), [report]);
  const allDevices = useMemo(
    () => [
      ...report.modules.ot_devices,
      ...report.modules.it_devices,
      ...report.modules.edge_devices,
    ],
    [report],
  );

  const device = useMemo<Device | undefined>(() => {
    if (entity?.type !== "device") return undefined;
    return allDevices.find((candidate) => deviceIps(candidate).includes(entity.id));
  }, [entity, allDevices]);

  const deviceClasses = useMemo(() => {
    if (entity?.type !== "device") return [];
    const classes: string[] = [];
    if (report.modules.ot_devices.some((candidate) => deviceIps(candidate).includes(entity.id))) classes.push("OT");
    if (report.modules.it_devices.some((candidate) => deviceIps(candidate).includes(entity.id))) classes.push("IT");
    if (report.modules.edge_devices.some((candidate) => deviceIps(candidate).includes(entity.id))) classes.push("Network");
    return classes;
  }, [entity, report]);

  const deviceConnections = useMemo(
    () =>
      entity?.type === "device"
        ? report.modules.connection_success_panel.connections.filter(
            (connection) =>
              connection["src_endpoint.ip"] === entity.id ||
              connection["dst_endpoint.ip"] === entity.id,
          )
        : [],
    [entity, report],
  );
  const deviceInbound = useMemo(
    () =>
      entity?.type === "device"
        ? deviceConnections.filter((connection) => connection["dst_endpoint.ip"] === entity.id)
        : [],
    [deviceConnections, entity],
  );
  const deviceOutbound = useMemo(
    () =>
      entity?.type === "device"
        ? deviceConnections.filter((connection) => connection["src_endpoint.ip"] === entity.id)
        : [],
    [deviceConnections, entity],
  );
  const devicePeers = useMemo(
    () =>
      entity?.type === "device"
        ? unique(
            deviceConnections.map((connection) =>
              connection["src_endpoint.ip"] === entity.id
                ? connection["dst_endpoint.ip"]
                : connection["src_endpoint.ip"],
            ),
          )
        : [],
    [deviceConnections, entity],
  );
  const deviceFindings = useMemo(
    () =>
      entity?.type === "device"
        ? allFindings.filter(
            (finding) => finding.ip === entity.id || finding.destination === entity.id,
          )
        : [],
    [entity, allFindings],
  );
  const suspicious = useMemo(
    () =>
      entity?.type === "device"
        ? report.modules.suspicious_outbound_connections_panel.filter(
            (connection) =>
              connection["src_endpoint.ip"] === entity.id ||
              connection["dst_endpoint.ip"] === entity.id,
          )
        : [],
    [entity, report],
  );
  const deviceMacs = useMemo(
    () =>
      entity?.type === "device"
        ? unique([
            device?.mac,
            ...deviceConnections.flatMap((connection) =>
              connection["src_endpoint.ip"] === entity.id
                ? [connection["src_device.mac"]]
                : connection["dst_endpoint.ip"] === entity.id
                  ? [connection["dst_device.mac"]]
                  : [],
            ),
          ])
        : [],
    [device, deviceConnections, entity],
  );
  const deviceManufacturers = useMemo(
    () =>
      entity?.type === "device"
        ? unique([
            device?.manufacturer,
            ...deviceConnections.flatMap((connection) =>
              connection["src_endpoint.ip"] === entity.id
                ? [connection["src_device.manufacturer"]]
                : connection["dst_endpoint.ip"] === entity.id
                  ? [connection["dst_device.manufacturer"]]
                  : [],
            ),
          ])
        : [],
    [device, deviceConnections, entity],
  );

  const finding = useMemo(
    () => (entity?.type === "finding" ? allFindings.find((item) => item.id === entity.id) : undefined),
    [entity, allFindings],
  );

  const service = entity?.type === "service" ? entity.id : finding?.service;
  const serviceDefinition = useMemo(
    () => (service ? report.modules.ot_services.find((item) => item["service.name"] === service) : undefined),
    [service, report],
  );
  const serviceSummary = useMemo(
    () =>
      service
        ? report.modules.service_count_panel.service_connections_count.known_services.find(
            (item) => item.name === service,
          )
        : undefined,
    [service, report],
  );
  const serviceRisks = useMemo(
    () =>
      service
        ? (Object.entries(report.modules.service_risk_breakdown_panel.risk_category_services) as [string, string[]][])
            .filter(([, services]) => services.includes(service))
            .map(([risk]) => risk)
        : [],
    [service, report],
  );
  const serviceFlows = useMemo(
    () =>
      service
        ? report.modules.connection_success_panel.connections.filter(
            (connection) =>
              connection["service.name"] === service ||
              connection["connection_info.protocol_name"] === service,
          )
        : [],
    [service, report],
  );
  const servicePorts = useMemo(
    () =>
      [...new Set(serviceFlows.map((connection) => connection["dst_endpoint.port"]).filter((port): port is number => typeof port === "number"))],
    [serviceFlows],
  );
  const serviceDevices = useMemo(
    () => unique(serviceFlows.flatMap((connection) => [connection["src_endpoint.ip"], connection["dst_endpoint.ip"]])),
    [serviceFlows],
  );
  const serviceIsOt = Boolean(service && serviceDefinition);
  const serviceIsKnown = Boolean(service && report.modules.service_count_panel.service_connections_count.known_services.some((item) => item.name === service));
  const serviceClassification = serviceIsOt ? "OT" : serviceIsKnown ? "IT" : "Other / Unclassified";
  const serviceFindings = useMemo(
    () => (service ? allFindings.filter((item) => item.service === service) : []),
    [service, allFindings],
  );

  const connection = useMemo(() => {
    if (entity?.type !== "connection") return undefined;
    const [src, dst, svc] = entity.id.split("|");
    const aggregate =
      report.modules.ot_cross_segment_lines_panel.lines.find(
        (item) =>
          item["src_endpoint.ip"] === src &&
          item["dst_endpoint.ip"] === dst &&
          item["service.name"] === svc,
      ) ||
      report.modules.suspicious_outbound_connections_panel.find(
        (item) =>
          item["src_endpoint.ip"] === src &&
          item["dst_endpoint.ip"] === dst &&
          item["service.name"] === svc,
      );
    if (aggregate) return aggregate;
    const flow = report.modules.connection_success_panel.connections.find(
      (item) =>
        item["src_endpoint.ip"] === src &&
        item["dst_endpoint.ip"] === dst &&
        (item["service.name"] ||
          item["connection_info.protocol_name"] ||
          `Port ${item["dst_endpoint.port"] ?? "—"}`) === svc,
    );
    return flow
      ? {
          "src_endpoint.ip": src,
          "dst_endpoint.ip": dst,
          "dst_endpoint.port": flow["dst_endpoint.port"] ?? 0,
          "service.name": svc,
          count: report.modules.connection_success_panel.connections.filter(
            (item) => item["src_endpoint.ip"] === src && item["dst_endpoint.ip"] === dst,
          ).length,
        }
      : undefined;
  }, [entity, report]);

  const connectionFlows = useMemo(() => {
    if (!connection) return [];
    return report.modules.connection_success_panel.connections.filter(
      (item) =>
        item["src_endpoint.ip"] === connection["src_endpoint.ip"] &&
        item["dst_endpoint.ip"] === connection["dst_endpoint.ip"] &&
        (item["service.name"] === connection["service.name"] ||
          item["connection_info.protocol_name"] === connection["service.name"] ||
          item["dst_endpoint.port"] === connection["dst_endpoint.port"]),
    );
  }, [connection, report]);

  const connectionFindings = useMemo(() => {
    if (!connection) return [];
    const src = connection["src_endpoint.ip"];
    const dst = connection["dst_endpoint.ip"];
    const svc = connection["service.name"];
    return allFindings.filter((item) => {
      const endpointMatch = !item.ip && !item.destination
        ? true
        : [src, dst].includes(item.ip || "") || [src, dst].includes(item.destination || "");
      const serviceMatch = !item.service || item.service === svc;
      return endpointMatch && serviceMatch;
    });
  }, [connection, allFindings]);

  const findingFlows = useMemo(() => {
    if (!finding) return [];
    return report.modules.connection_success_panel.connections
      .filter((connection) => {
        const src = connection["src_endpoint.ip"];
        const dst = connection["dst_endpoint.ip"];
        if (finding.ip && src !== finding.ip && dst !== finding.ip) return false;
        if (finding.destination && src !== finding.destination && dst !== finding.destination) return false;
        if (finding.service && connection["service.name"] !== finding.service) return false;
        return true;
      })
      .slice(0, 100);
  }, [finding, report]);
  const findingDevices = useMemo(() => {
    const ids = new Set<string>();
    findingFlows.forEach((flow) => {
      if (flow["src_endpoint.ip"]) ids.add(flow["src_endpoint.ip"]!);
      if (flow["dst_endpoint.ip"]) ids.add(flow["dst_endpoint.ip"]!);
    });
    if (finding?.ip) ids.add(finding.ip);
    if (finding?.destination) ids.add(finding.destination);
    return [...ids];
  }, [finding, findingFlows]);
  const findingServices = useMemo(() => {
    const names = new Set<string>();
    findingFlows.forEach((flow) => {
      if (flow["service.name"]) names.add(flow["service.name"]!);
    });
    if (finding?.service) names.add(finding.service);
    return [...names];
  }, [finding, findingFlows]);

  if (!entity) return null;

  const editableFields: Array<{ key: string; label: string; original: string; type?: "text" | "textarea" | "select"; options?: string[] }> =
    entity.type === "finding"
      ? [
          { key: "title", label: "Display title", original: finding?.title || entity.id },
          { key: "severity", label: "Severity", original: finding?.severity || "info", type: "select", options: ["critical", "high", "medium", "low", "info"] },
          { key: "status", label: "Status", original: "Open", type: "select", options: ["Open", "Reviewed", "Accepted", "False Positive", "Resolved"] },
          { key: "description", label: "Description", original: finding?.summary || "—", type: "textarea" },
          { key: "tags", label: "Tags", original: finding?.tags?.join(", ") || "—" },
        ]
      : entity.type === "device"
        ? [
            { key: "name", label: "Friendly name", original: entity.id },
            { key: "deviceType", label: "Device type", original: deviceClasses.join(", ") || "Unknown" },
            { key: "manufacturer", label: "Manufacturer", original: deviceManufacturers.join(", ") || "—" },
            { key: "purdueLevel", label: "Purdue level", original: "—" },
            { key: "siteZone", label: "Site / zone", original: deviceSubnets(device).join(", ") || "—" },
            { key: "criticality", label: "Criticality", original: "Unspecified", type: "select", options: ["Unspecified", "Low", "Medium", "High", "Critical"] },
            { key: "tags", label: "Tags", original: "—" },
          ]
        : entity.type === "service"
          ? [
              { key: "name", label: "Friendly service name", original: entity.id },
              { key: "expectation", label: "Expected state", original: "Unknown", type: "select", options: ["Unknown", "Expected", "Unexpected"] },
              { key: "description", label: "Description / purpose", original: serviceDefinition?.["service.description"] || "—", type: "textarea" },
              { key: "ownerSystem", label: "Owner / system", original: "—" },
              { key: "tags", label: "Tags", original: "—" },
            ]
          : [
              { key: "description", label: "Friendly description", original: connection ? `${connection["src_endpoint.ip"]} → ${connection["dst_endpoint.ip"]} (${connection["service.name"] || "unknown service"})` : entity.id, type: "textarea" },
              { key: "expectation", label: "Expected state", original: "Unknown", type: "select", options: ["Unknown", "Expected", "Unexpected"] },
              { key: "authorization", label: "Authorization", original: "Unknown", type: "select", options: ["Unknown", "Authorized", "Unauthorized"] },
              { key: "purpose", label: "Purpose", original: "—", type: "textarea" },
              { key: "tags", label: "Tags", original: "—" },
            ];

  const cleanedOverrideDraft = Object.fromEntries(
    editableFields.flatMap((field) => {
      const value = (overrideDraft[field.key] || "").trim();
      if (!value || value === field.original || (field.original === "—" && !value)) return [];
      return [[field.key, value]];
    }),
  ) as Record<string, string>;
  const overrideCount = Object.keys(overrides).length;
  const displayTitle = entity.type === "finding"
    ? (overrides.title || finding?.title || entity.id)
    : entity.type === "device"
      ? (overrides.name || entity.id)
      : entity.type === "service"
        ? (overrides.name || entity.id)
        : (overrides.description || entity.id);
  const title = displayTitle;

  return (
    <>
      <button className="entity-drawer-backdrop" onClick={onClose} aria-label="Close details" />
      <aside className="entity-drawer" role="dialog" aria-modal="true" aria-labelledby="entity-drawer-title">
        <header>
          <div>
            <p>{entity.type} details</p>
            <h2 id="entity-drawer-title">{title}</h2>
          </div>
          <div className="entity-drawer-header-actions">
            <button type="button" className={`entity-edit-button${overrideCount ? " has-edits" : ""}`} onClick={() => { setOverrideDraft(overrides); setOverrideEditing((value) => !value); }} aria-label={overrideEditing ? "Cancel editing" : `Edit ${entity.type}`} title={overrideEditing ? "Cancel editing" : `Edit ${entity.type}`}>
              <span aria-hidden="true">✎</span>
            </button>
            <button type="button" onClick={onClose} aria-label="Close details">×</button>
          </div>
        </header>
        <div className="entity-drawer-body">
          <DrawerSection title="Review details">
            {overrideEditing ? (
              <div className="entity-edit-form">
                {editableFields.map((field) => (
                  <label key={field.key} className="entity-edit-field">
                    <span>{field.label}</span>
                    {field.type === "textarea" ? (
                      <textarea rows={3} value={overrideDraft[field.key] ?? field.original} onChange={(event) => setOverrideDraft((current) => ({ ...current, [field.key]: event.target.value }))} />
                    ) : field.type === "select" ? (
                      <select value={overrideDraft[field.key] ?? field.original} onChange={(event) => setOverrideDraft((current) => ({ ...current, [field.key]: event.target.value }))}>
                        {(field.options || []).map((option) => <option key={option} value={option}>{option}</option>)}
                      </select>
                    ) : (
                      <input type="text" value={overrideDraft[field.key] ?? field.original} onChange={(event) => setOverrideDraft((current) => ({ ...current, [field.key]: event.target.value }))} />
                    )}
                    <small>Generated value: {field.original}</small>
                  </label>
                ))}
                <div className="entity-edit-actions">
                  {overrideCount > 0 && <button type="button" className="entity-reset-edits" onClick={() => { onResetOverrides(); setOverrideDraft({}); setOverrideEditing(false); }}>Reset edits</button>}
                  <button type="button" className="entity-edit-cancel" onClick={() => { setOverrideDraft(overrides); setOverrideEditing(false); }}>Cancel</button>
                  <button type="button" className="entity-edit-save" onClick={() => { onSaveOverrides(cleanedOverrideDraft); setOverrideEditing(false); }}>Save</button>
                </div>
              </div>
            ) : (
              <div className="entity-review-fields">
                {editableFields.map((field) => {
                  const edited = Boolean(overrides[field.key]);
                  const value = overrides[field.key] || field.original;
                  return (
                    <div key={field.key} className={`entity-review-field${edited ? " is-edited" : ""}`}>
                      <span>{field.label}{edited && <em>Edited</em>}</span>
                      <strong>{value}</strong>
                      {edited && <small>Generated value: {field.original}</small>}
                    </div>
                  );
                })}
                {!overrideCount && <p className="entity-edit-hint">Use the pencil in the drawer header to add reviewed display values without changing the underlying Zeek or detector evidence.</p>}
              </div>
            )}
          </DrawerSection>

          {entity.type === "device" && (
            <>
              <div className="entity-identity">
                <span className="entity-type type-device">Device</span>
                <strong><PivotValue filter={{ key: "ip", value: entity.id, label: "Device" }} filters={filters} onFilter={onFilter}>{entity.id}</PivotValue></strong>
                <small className={overrides.manufacturer ? "entity-inline-edited" : ""}>{overrides.manufacturer || deviceManufacturers[0] || "Manufacturer not identified"}</small>
              </div>
              <div className="entity-stat-grid">
                <div><span>Observed flows</span><strong>{deviceConnections.length}</strong></div>
                <div><span>Connected peers</span><strong>{devicePeers.length}</strong></div>
                <div><span>Inbound</span><strong>{deviceInbound.length}</strong></div>
                <div><span>Outbound</span><strong>{deviceOutbound.length}</strong></div>
                <div><span>Associated findings</span><strong>{deviceFindings.length}</strong></div>
                <div><span>Services</span><strong>{unique([...(device?.incoming_services || []), ...(device?.sent_services || [])]).length}</strong></div>
              </div>
              <DrawerSection title="Identity and network">
                <KeyValue label="Manufacturer" value={overrides.manufacturer || (deviceManufacturers.length ? deviceManufacturers.join(", ") : "—")} edited={Boolean(overrides.manufacturer)} />
                <KeyValue label="MACs" value={deviceMacs.length ? deviceMacs.join(", ") : "—"} />
                <PivotKeyValue label="IPs">{(deviceIps(device).length ? deviceIps(device) : [entity.id]).map((ip) => <PivotValue key={ip} filter={{ key: "ip", value: ip, label: "Device" }} filters={filters} onFilter={onFilter}>{ip}</PivotValue>)}</PivotKeyValue>
                <PivotKeyValue label="Subnets">{deviceSubnets(device).length ? deviceSubnets(device).map((subnet) => <PivotValue key={subnet} filter={{ key: "subnet", value: subnet, label: "Subnet" }} filters={filters} onFilter={onFilter}>{subnet}</PivotValue>) : <strong>—</strong>}</PivotKeyValue>
                <PivotKeyValue label="Device classes">{deviceClasses.length ? deviceClasses.map((deviceClass) => <PivotValue key={deviceClass} filter={{ key: "deviceClass", value: deviceClass, label: "Class" }} filters={filters} onFilter={onFilter}>{deviceClass}</PivotValue>) : <strong>Unknown</strong>}</PivotKeyValue>
              </DrawerSection>
              <DrawerSection title="Observed services">
                <PivotKeyValue label="Services in">{device?.incoming_services?.length ? device.incoming_services.map((name) => <PivotValue key={name} filter={{ key: "service", value: name, label: "Service" }} filters={filters} onFilter={onFilter}>{name}</PivotValue>) : <strong>—</strong>}</PivotKeyValue>
                <PivotKeyValue label="Services out">{device?.sent_services?.length ? device.sent_services.map((name) => <PivotValue key={name} filter={{ key: "service", value: name, label: "Service" }} filters={filters} onFilter={onFilter}>{name}</PivotValue>) : <strong>—</strong>}</PivotKeyValue>
              </DrawerSection>
              <DrawerSection title={`Connections (${deviceConnections.length})`}>
                <DeviceFlowTable rows={deviceConnections} deviceId={entity.id} filters={filters} onFilter={onFilter} />
              </DrawerSection>
              <DrawerSection title={`Associated findings (${deviceFindings.length})`}>
                <FindingList findings={deviceFindings} />
              </DrawerSection>
              {suspicious.length > 0 && (
                <DrawerSection title="Suspicious outbound observations">
                  <ul className="drawer-list">
                    {suspicious.slice(0, 12).map((item, index) => (
                      <li key={`${item["src_endpoint.ip"]}-${item["dst_endpoint.ip"]}-${index}`}>
                        <span><PivotValue filter={{ key: "ip", value: item["dst_endpoint.ip"], label: "Device" }} filters={filters} onFilter={onFilter}>{item["dst_endpoint.ip"]}</PivotValue>:<PivotValue filter={{ key: "port", value: String(item["dst_endpoint.port"]), label: "Port" }} filters={filters} onFilter={onFilter}>{item["dst_endpoint.port"]}</PivotValue></span>
                        <strong>{item["service.name"] ? <PivotValue filter={{ key: "service", value: item["service.name"], label: "Service" }} filters={filters} onFilter={onFilter}>{item["service.name"]}</PivotValue> : "—"} · {item.count}</strong>
                      </li>
                    ))}
                  </ul>
                </DrawerSection>
              )}
            </>
          )}

          {entity.type === "service" && (
            <>
              <div className="entity-identity">
                <span className="entity-type type-service">Service</span>
                <strong><PivotValue filter={{ key: "service", value: entity.id, label: "Service" }} filters={filters} onFilter={onFilter}>{entity.id}</PivotValue></strong>
                <small>{serviceClassification} service</small>
              </div>
              <div className="entity-stat-grid">
                <div><span>Observed flows</span><strong>{serviceSummary?.count || serviceFlows.length}</strong></div>
                <div><span>Connected devices</span><strong>{serviceDevices.length}</strong></div>
                <div><span>Ports</span><strong>{servicePorts.length}</strong></div>
                <div><span>Associated findings</span><strong>{serviceFindings.length}</strong></div>
              </div>
              <DrawerSection title="Service overview">
                <PivotKeyValue label="Service"><PivotValue filter={{ key: "service", value: entity.id, label: "Service" }} filters={filters} onFilter={onFilter}>{entity.id}</PivotValue></PivotKeyValue>
                <KeyValue label="Description" value={overrides.description || serviceDefinition?.["service.description"] || "—"} edited={Boolean(overrides.description)} />
                <KeyValue label="Information" value={serviceDefinition?.["service.information_categories"] || "—"} />
                <KeyValue label="Service classification" value={serviceClassification} />
                <PivotKeyValue label="Port(s)">{servicePorts.length ? servicePorts.map((port) => <PivotValue key={port} filter={{ key: "port", value: String(port), label: "Port" }} filters={filters} onFilter={onFilter}>{port}</PivotValue>) : <strong>—</strong>}</PivotKeyValue>
              </DrawerSection>
              {serviceRisks.length > 0 && <DrawerSection title="Risk classifications"><div className="entity-tags">{serviceRisks.map((risk) => <PivotValue key={risk} filter={{ key: "risk", value: risk, label: "Risk" }} filters={filters} onFilter={onFilter}>{risk}</PivotValue>)}</div></DrawerSection>}
              <DrawerSection title={`Observed connections (${serviceFlows.length})`}><FlowTable rows={serviceFlows} filters={filters} onFilter={onFilter} /></DrawerSection>
              <DrawerSection title={`Associated findings (${serviceFindings.length})`}><FindingList findings={serviceFindings} /></DrawerSection>
            </>
          )}

          {entity.type === "connection" && connection && (
            <>
              <div className="entity-identity">
                <span className="entity-type type-connection">Connection</span>
                <strong><PivotValue filter={{ key: "ip", value: connection["src_endpoint.ip"], label: "Device" }} filters={filters} onFilter={onFilter}>{connection["src_endpoint.ip"]}</PivotValue> → <PivotValue filter={{ key: "ip", value: connection["dst_endpoint.ip"], label: "Device" }} filters={filters} onFilter={onFilter}>{connection["dst_endpoint.ip"]}</PivotValue></strong>
                <small>{connection["service.name"] ? <PivotValue filter={{ key: "service", value: connection["service.name"], label: "Service" }} filters={filters} onFilter={onFilter}>{connection["service.name"]}</PivotValue> : "—"} · port <PivotValue filter={{ key: "port", value: String(connection["dst_endpoint.port"]), label: "Port" }} filters={filters} onFilter={onFilter}>{connection["dst_endpoint.port"]}</PivotValue></small>
              </div>
              <div className="entity-stat-grid">
                <div><span>Aggregated observations</span><strong>{connection.count}</strong></div>
                <div><span>Flow records</span><strong>{connectionFlows.length}</strong></div>
                <div><span>Associated findings</span><strong>{connectionFindings.length}</strong></div>
                <div><span>Successful flows</span><strong>{connectionFlows.filter((flow) => flow.success).length}</strong></div>
              </div>
              <DrawerSection title="Connection overview">
                <PivotKeyValue label="Source"><PivotValue filter={{ key: "ip", value: connection["src_endpoint.ip"], label: "Device" }} filters={filters} onFilter={onFilter}>{connection["src_endpoint.ip"]}</PivotValue></PivotKeyValue>
                <PivotKeyValue label="Destination"><PivotValue filter={{ key: "ip", value: connection["dst_endpoint.ip"], label: "Device" }} filters={filters} onFilter={onFilter}>{connection["dst_endpoint.ip"]}</PivotValue></PivotKeyValue>
                <PivotKeyValue label="Service">{connection["service.name"] ? <PivotValue filter={{ key: "service", value: connection["service.name"], label: "Service" }} filters={filters} onFilter={onFilter}>{connection["service.name"]}</PivotValue> : <strong>—</strong>}</PivotKeyValue>
                <PivotKeyValue label="Port"><PivotValue filter={{ key: "port", value: String(connection["dst_endpoint.port"]), label: "Port" }} filters={filters} onFilter={onFilter}>{connection["dst_endpoint.port"]}</PivotValue></PivotKeyValue>
              </DrawerSection>
              <DrawerSection title={`Observed flow data (${connectionFlows.length})`}><FlowTable rows={connectionFlows} filters={filters} onFilter={onFilter} /></DrawerSection>
              <DrawerSection title={`Associated findings (${connectionFindings.length})`}><FindingList findings={connectionFindings} /></DrawerSection>
            </>
          )}

          {entity.type === "finding" && finding && (
            <>
              <div className="entity-identity"><span className={`entity-type type-${overrides.severity || finding.severity}`}>{overrides.severity || finding.severity} finding</span><strong className={overrides.title ? "entity-inline-edited" : ""}>{overrides.title || finding.title}</strong><small>{finding.moduleId ? `${finding.moduleId} · ` : ""}{finding.detectionBasis || "derived"}</small></div>
              <div className="finding-explain-grid"><div><span>Confidence</span><strong className={`finding-confidence confidence-${(finding.confidence || "unspecified").toLowerCase()}`}>{finding.confidence || "unspecified"}</strong></div><div><span>Detection basis</span><strong>{finding.detectionBasis || "derived"}</strong></div><div><span>Retained evidence</span><strong>{finding.count ?? "—"}</strong></div><div><span>Module</span><strong>{finding.moduleId || "report-derived"}</strong></div></div>
              <section className="why-flagged" aria-labelledby="why-flagged-heading">
                <div className="why-flagged-heading">
                  <div>
                    <p>Decision explanation</p>
                    <h3 id="why-flagged-heading">Why was this flagged?</h3>
                  </div>
                  <span className={`why-flagged-confidence confidence-${(finding.confidence || "unspecified").toLowerCase()}`}>{finding.confidence || "unspecified"} confidence</span>
                </div>
                <p className="why-flagged-intro">eleVADR reached this finding by combining retained network evidence, the detector rule, and the Detection Context available when the report was generated.</p>
                <ol className="why-flagged-steps">
                  <li><span>1</span><div><strong>What was observed</strong><p>{finding.observedEvidence?.[0] || "The detector reported activity, but this report does not retain a concise observation summary."}</p></div></li>
                  <li><span>2</span><div><strong>What rule evaluated it</strong><p>{finding.moduleId ? `${finding.moduleId} evaluated the evidence using ${finding.detectionBasis || "its detector logic"}.` : `The report evaluated this evidence using ${finding.detectionBasis || "report-derived logic"}.`}</p></div></li>
                  <li><span>3</span><div><strong>What context affected the decision</strong><p>{finding.contextEvidence?.[0] || "No Detection Context detail was retained for this finding."}</p></div></li>
                  <li><span>4</span><div><strong>Why the result became a finding</strong><p>{overrides.description || finding.inference || finding.summary}</p></div></li>
                </ol>
                <p className="why-flagged-note">Observed traffic is evidence, not authorization. Only authoritative Detection Context or detector policy should be used to document an approved exception.</p>
              </section>
              <DrawerSection title="Observed evidence"><EvidenceList items={finding.observedEvidence} /><div className="entity-support-group"><strong>Devices</strong><div className="entity-tags">{findingDevices.length ? findingDevices.map((ip) => <PivotValue key={ip} filter={{ key: "ip", value: ip, label: "Device" }} filters={filters} onFilter={onFilter}>{ip}</PivotValue>) : <span>—</span>}</div></div><div className="entity-support-group"><strong>Services</strong><div className="entity-tags">{findingServices.length ? findingServices.map((name) => <PivotValue key={name} filter={{ key: "service", value: name, label: "Service" }} filters={filters} onFilter={onFilter}>{name}</PivotValue>) : <span>—</span>}</div></div><FlowTable rows={findingFlows} filters={filters} onFilter={onFilter} /></DrawerSection>
              {finding.provenanceEvidence?.length ? <DrawerSection title="Zeek provenance"><EvidenceList items={finding.provenanceEvidence} /></DrawerSection> : null}
              <DrawerSection title="Detection Context / policy"><EvidenceList items={finding.contextEvidence} /><p className="drawer-policy-note">Observed facts and authoritative policy are shown separately. A Zeek observation does not itself create an allowlist, control authorization, or approved segment path.</p></DrawerSection>
              <DrawerSection title="Detector inference"><p className={`drawer-copy${overrides.description ? " entity-inline-edited" : ""}`}>{overrides.description || finding.inference || finding.summary}</p>{finding.tags?.length ? <div className="finding-tag-list">{finding.tags.map((tag) => <span key={tag}>{tag}</span>)}</div> : null}</DrawerSection>
              <DrawerSection title="Legitimate context changes"><EvidenceList items={finding.suppressionGuidance} /></DrawerSection>
              <DrawerSection title="Recommended response"><p className="drawer-copy">{finding.remediation}</p></DrawerSection>
              <DrawerSection title="Investigation pivots"><div className="drawer-actions">{finding.service && <PivotValue filter={{ key: "service", value: finding.service!, label: "Service" }} filters={filters} onFilter={onFilter}>Service: {finding.service}</PivotValue>}{finding.ip && <PivotValue filter={{ key: "ip", value: finding.ip!, label: "Device" }} filters={filters} onFilter={onFilter}>Device: {finding.ip}</PivotValue>}<PivotValue filter={{ key: "risk", value: finding.severity, label: "Risk" }} filters={filters} onFilter={onFilter}>Severity: {finding.severity}</PivotValue></div></DrawerSection>
            </>
          )}

          <DrawerSection title="Notes">
            {noteEditing ? (
              <div className="drawer-notes-editor">
                <label htmlFor="entity-note-text">Notes for this {entity.type}</label>
                <textarea
                  id="entity-note-text"
                  value={noteDraft}
                  onChange={(event) => setNoteDraft(event.target.value)}
                  placeholder={`Add notes about this ${entity.type}...`}
                  rows={5}
                  autoFocus
                />
                <div className="drawer-notes-actions">
                  <button type="button" className="drawer-note-cancel" onClick={() => { setNoteDraft(note); setNoteEditing(false); }}>Cancel</button>
                  <button type="button" className="drawer-note-save" onClick={() => { onSaveNote(noteDraft); setNoteEditing(false); }}>Save</button>
                </div>
              </div>
            ) : note.trim() ? (
              <div className="drawer-note-saved">
                <p>{note}</p>
                <div className="drawer-notes-actions">
                  <button type="button" className="drawer-note-delete" onClick={() => { onDeleteNote(); setNoteDraft(""); }}>Delete</button>
                  <button type="button" className="drawer-note-edit" onClick={() => { setNoteDraft(note); setNoteEditing(true); }}>Edit</button>
                </div>
              </div>
            ) : (
              <div className="drawer-note-empty">
                <p>No notes have been added for this {entity.type}.</p>
                <button type="button" className="drawer-note-add" onClick={() => { setNoteDraft(""); setNoteEditing(true); }}>+ Add note</button>
              </div>
            )}
            <p className="drawer-note-hint">Notes are stored separately from detector and Zeek evidence.</p>
          </DrawerSection>
        </div>
      </aside>
    </>
  );
};

const EvidenceList: React.FC<{ items?: string[] }> = ({ items }) =>
  items?.length ? <ul className="finding-evidence-list">{items.map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}</ul> : <p className="drawer-copy">No additional detail is available in this report.</p>;
const DrawerSection: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => <section className="drawer-section"><h3>{title}</h3>{children}</section>;
const KeyValue: React.FC<{ label: string; value: string | number; edited?: boolean }> = ({ label, value, edited = false }) => <div className={`drawer-keyvalue${edited ? " is-edited" : ""}`}><span>{label}{edited && <em>Edited</em>}</span><strong>{value}</strong></div>;
const PivotKeyValue: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => <div className="drawer-keyvalue"><span>{label}</span><div className="drawer-pivot-values">{children}</div></div>;

const FindingList: React.FC<{ findings: ReturnType<typeof deriveFindings> }> = ({ findings }) =>
  findings.length ? (
    <ul className="drawer-list drawer-finding-list">
      {findings.slice(0, 15).map((item) => <li key={item.id}><span><strong>{item.title}</strong><small>{item.moduleId || "Report-derived"}</small></span><strong>{item.severity}</strong></li>)}
    </ul>
  ) : <p className="drawer-copy">No findings in this report are directly associated with this item.</p>;

const FlowTable: React.FC<{ rows: ServiceConnectionDetail[]; filters: InvestigationFilter[]; onFilter: (filter: InvestigationFilter) => void }> = ({ rows, filters, onFilter }) =>
  rows.length ? <div className="drawer-flow-table-wrap"><table className="drawer-flow-table"><thead><tr><th>Source</th><th>Destination</th><th>Service</th><th>Protocol</th><th>State</th><th>Result</th></tr></thead><tbody>{rows.slice(0, 30).map((row, index) => <tr key={`${row["src_endpoint.ip"]}-${row["dst_endpoint.ip"]}-${row["src_endpoint.port"]}-${row["dst_endpoint.port"]}-${index}`}><td>{row["src_endpoint.ip"] ? <PivotValue filter={{ key: "ip", value: row["src_endpoint.ip"]!, label: "Device" }} filters={filters} onFilter={onFilter}>{row["src_endpoint.ip"]}</PivotValue> : "—"}:{row["src_endpoint.port"] != null ? <PivotValue filter={{ key: "port", value: String(row["src_endpoint.port"]), label: "Port" }} filters={filters} onFilter={onFilter}>{row["src_endpoint.port"]}</PivotValue> : "—"}</td><td>{row["dst_endpoint.ip"] ? <PivotValue filter={{ key: "ip", value: row["dst_endpoint.ip"]!, label: "Device" }} filters={filters} onFilter={onFilter}>{row["dst_endpoint.ip"]}</PivotValue> : "—"}:{row["dst_endpoint.port"] != null ? <PivotValue filter={{ key: "port", value: String(row["dst_endpoint.port"]), label: "Port" }} filters={filters} onFilter={onFilter}>{row["dst_endpoint.port"]}</PivotValue> : "—"}</td><td>{row["service.name"] ? <PivotValue filter={{ key: "service", value: row["service.name"]!, label: "Service" }} filters={filters} onFilter={onFilter}>{row["service.name"]}</PivotValue> : "—"}</td><td>{row["connection_info.protocol_name"] || "—"}</td><td>{row.state ? <PivotValue filter={{ key: "zeekState", value: String(row.state), label: "Zeek State" }} filters={filters} onFilter={onFilter}>{String(row.state)}</PivotValue> : "—"}</td><td>{row.success ? "Successful" : "Unsuccessful"}</td></tr>)}</tbody></table>{rows.length > 30 && <p className="drawer-flow-note">Showing 30 of {rows.length} available flow records.</p>}</div> : <p className="drawer-copy">No flow-level records are available in this report for the selected item.</p>;

const DeviceFlowTable: React.FC<{ rows: ServiceConnectionDetail[]; deviceId: string; filters: InvestigationFilter[]; onFilter: (filter: InvestigationFilter) => void }> = ({ rows, deviceId, filters, onFilter }) =>
  rows.length ? <div className="drawer-flow-table-wrap"><table className="drawer-flow-table"><thead><tr><th>Direction</th><th>Peer</th><th>Service</th><th>Port</th><th>Protocol</th><th>State</th><th>Result</th></tr></thead><tbody>{rows.slice(0, 30).map((row, index) => { const outbound = row["src_endpoint.ip"] === deviceId; const peer = outbound ? row["dst_endpoint.ip"] : row["src_endpoint.ip"]; const port = outbound ? row["dst_endpoint.port"] : row["src_endpoint.port"]; return <tr key={`${row["src_endpoint.ip"]}-${row["dst_endpoint.ip"]}-${index}`}><td>{outbound ? "Outbound" : "Inbound"}</td><td>{peer ? <PivotValue filter={{ key: "ip", value: peer, label: "Device" }} filters={filters} onFilter={onFilter}>{peer}</PivotValue> : "—"}</td><td>{row["service.name"] ? <PivotValue filter={{ key: "service", value: row["service.name"]!, label: "Service" }} filters={filters} onFilter={onFilter}>{row["service.name"]}</PivotValue> : "—"}</td><td>{port != null ? <PivotValue filter={{ key: "port", value: String(port), label: "Port" }} filters={filters} onFilter={onFilter}>{port}</PivotValue> : "—"}</td><td>{row["connection_info.protocol_name"] || "—"}</td><td>{row.state || "—"}</td><td>{row.success ? "Successful" : "Unsuccessful"}</td></tr>; })}</tbody></table>{rows.length > 30 && <p className="drawer-flow-note">Showing 30 of {rows.length} available flow records.</p>}</div> : <p className="drawer-copy">No flow-level connection records are available for this device.</p>;

export default EntityDrawer;
