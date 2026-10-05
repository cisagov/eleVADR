import React, { useEffect, useMemo, useRef, useState } from "react";
import { ElevadrReport } from "../../types/Report";
import { InvestigationFilter, SelectedEntity } from "../../types/Investigation";
import "./ReportSearch.css";

interface SearchResult { label:string; meta:string; target:string; kind:string; filter?:InvestigationFilter; entity?:SelectedEntity; command?:()=>void; }
interface Props { report:ElevadrReport; onFilter?:(filter:InvestigationFilter)=>void; onSelect?:(entity:SelectedEntity)=>void; }

const ReportSearch: React.FC<Props> = ({ report, onFilter, onSelect }) => {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const rootRef = useRef<HTMLDivElement>(null);

  const records = useMemo<SearchResult[]>(() => {
    const devices = [
      ...report.modules.ot_devices.map((device) => ({ device, kind: "OT devices" })),
      ...report.modules.it_devices.map((device) => ({ device, kind: "IT devices" })),
      ...report.modules.edge_devices.map((device) => ({ device, kind: "Network devices" })),
    ].flatMap(({ device, kind }) => (device.ip_addresses || device.ipv4_ips || []).map((ip) => ({
      label: ip,
      meta: [device.manufacturer, ...(device.incoming_services || []).slice(0, 3)].filter(Boolean).join(" · ") || "Observed device",
      target: "topology",
      kind,
      filter: { key:"ip", value:ip, label:"Device" } as InvestigationFilter,
      entity: { type:"device", id:ip } as SelectedEntity,
    })));

    const services = report.modules.ot_services.map((service) => ({
      label: service["service.name"],
      meta: service["service.description"] || service["service.risk_categories"] || "OT service",
      target: "overview",
      kind: "Services",
      filter: { key:"service", value:service["service.name"], label:"Service" } as InvestigationFilter,
      entity: { type:"service", id:service["service.name"] } as SelectedEntity,
    }));

    const outbound = report.modules.suspicious_outbound_connections_panel.map((connection) => ({
      label: `${connection["src_endpoint.ip"]} → ${connection["dst_endpoint.ip"]}:${connection["dst_endpoint.port"]}`,
      meta: `${connection["service.name"]} · ${connection.count} observations`,
      target: "topology",
      kind: "Suspicious connections",
      filter: { key:"ip", value:connection["src_endpoint.ip"], label:"Device" } as InvestigationFilter,
      entity: { type:"connection", id:`${connection["src_endpoint.ip"]}|${connection["dst_endpoint.ip"]}|${connection["service.name"]}` } as SelectedEntity,
    }));

    const commands:SearchResult[] = [
      { label:"Show suspicious paths", meta:"Open the topology focused on suspicious communications", target:"topology", kind:"Quick actions", command:()=>document.getElementById("topology")?.scrollIntoView({behavior:"smooth",block:"start"}) },
      { label:"Show OT devices", meta:"Filter the report to operational technology devices", target:"topology", kind:"Quick actions", filter:{key:"deviceClass",value:"OT",label:"Class"} },
      { label:"Review findings", meta:"Jump to prioritized security observations", target:"findings", kind:"Quick actions" },
    ];

    return [...commands, ...devices, ...services, ...outbound];
  }, [report]);

  const results = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return [];
    return records.filter((item) => `${item.label} ${item.meta} ${item.kind}`.toLowerCase().includes(normalized)).slice(0, 12);
  }, [query, records]);

  const closeSearch = () => {
    setOpen(false);
    setQuery("");
  };

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) closeSearch();
    };
    document.addEventListener("mousedown", onPointerDown);
    return () => document.removeEventListener("mousedown", onPointerDown);
  }, [open]);

  useEffect(() => {
    if (open) window.setTimeout(() => inputRef.current?.focus(), 0);
  }, [open]);

  const select = (result: SearchResult) => {
    closeSearch();
    // Entity results follow the report-wide interaction contract: selecting the
    // result opens details. Filtering is a separate, explicit action. Quick
    // actions without an entity may still apply a report filter directly.
    if (result.entity) onSelect?.(result.entity);
    else if (result.filter) onFilter?.(result.filter);
    result.command?.();
    if(!result.command) document.getElementById(result.target)?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const groups = useMemo(() => {
    const map = new Map<string, SearchResult[]>();
    results.forEach(result => map.set(result.kind,[...(map.get(result.kind)||[]),result]));
    return [...map.entries()];
  },[results]);

  return (
    <div className="report-search-popover" ref={rootRef}>
      <button
        type="button"
        className="top-action-button report-search-trigger"
        aria-label="Search report"
        aria-haspopup="dialog"
        aria-expanded={open}
        title="Search report"
        onClick={() => setOpen((current) => !current)}
      >
        <svg className="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6"/><path d="m16 16 4 4"/></svg>
        <span>Search</span>
      </button>

      {open && (
        <div className="report-search-popup" role="dialog" aria-label="Search report">
          <div className="report-search">
            <svg className="report-search-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6"/><path d="m16 16 4 4"/></svg>
            <input
              ref={inputRef}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Escape") closeSearch();
                if(event.key === "Enter" && results[0]) select(results[0]);
              }}
              placeholder="Search devices, IPs, services, findings, or commands…"
              aria-label="Search report"
              aria-expanded={Boolean(query.trim())}
            />
          </div>
          {query.trim() && (
            <div className="report-search-results" role="listbox" aria-label="Report search results">
              {groups.length > 0 ? groups.map(([kind,items])=><div className="search-result-group" key={kind}><div className="search-result-group-title">{kind}</div>{items.map((result,index)=>(
                <button type="button" role="option" aria-selected="false" key={`${result.kind}-${result.label}-${index}`} onClick={() => select(result)}>
                  <strong>{result.label}</strong><small>{result.meta}</small>
                </button>
              ))}</div>) : <div className="report-search-empty">No matching report entities or commands.</div>}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
export default ReportSearch;
