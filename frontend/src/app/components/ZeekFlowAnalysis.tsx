import React, { useEffect, useMemo, useState } from "react";
import { ElevadrReport, ConnectionSuccessLine } from "../types/Report";
import { InvestigationFilter, SelectedEntity } from "../types/Investigation";
import Panel from "./Panel/Panel";
import PivotValue from "./PivotValue/PivotValue";
import "./ZeekFlowAnalysis.css";

interface Props {
  report: ElevadrReport;
  filters: InvestigationFilter[];
  onFilter: (filter: InvestigationFilter) => void;
  onSelect: (entity: SelectedEntity) => void;
}

const val = (row: ConnectionSuccessLine, key: string) =>
  String((row as unknown as Record<string, unknown>)[key] ?? "");

const ZeekFlowAnalysis: React.FC<Props> = ({
  report,
  filters,
  onFilter,
  onSelect,
}) => {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const rows = useMemo(
    () =>
      report.modules.connection_success_panel.connections.filter((row) => {
        const src = val(row, "src_endpoint.ip");
        const dst = val(row, "dst_endpoint.ip");
        const service =
          val(row, "service.name") ||
          val(row, "connection_info.protocol_name") ||
          `port:${val(row, "dst_endpoint.port")}`;
        const srcSubnet = val(row, "src_endpoint.subnet");
        const dstSubnet = val(row, "dst_endpoint.subnet");
        if (
          query &&
          ![
            src,
            dst,
            service,
            row.state,
            row.history,
            srcSubnet,
            dstSubnet,
          ].some((x) =>
            String(x || "")
              .toLowerCase()
              .includes(query.toLowerCase()),
          )
        )
          return false;
        return filters.every((f) => {
          if (f.key === "ip") return src === f.value || dst === f.value;
          if (f.key === "service")
            return (
              service === f.value ||
              val(row, "service.name") === f.value ||
              val(row, "connection_info.protocol_name") === f.value
            );
          if (f.key === "subnet")
            return srcSubnet === f.value || dstSubnet === f.value;
          if (f.key === "port")
            return (
              val(row, "src_endpoint.port") === f.value ||
              val(row, "dst_endpoint.port") === f.value
            );
          if (f.key === "zeekState") return String(row.state || "") === f.value;
          return true;
        });
      }),
    [report, filters, query],
  );

  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  useEffect(() => setPage(1), [query, filters, pageSize]);
  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  const start = (page - 1) * pageSize;
  const pageRows = rows.slice(start, start + pageSize);
  const first = rows.length ? start + 1 : 0;
  const last = Math.min(start + pageSize, rows.length);

  return (
    <Panel id="zeek-flow-analysis" title="Zeek Flow Analysis">
      <div className="zeek-flow-analysis">
        <div className="zeek-flow-toolbar">
          <p>
            Flow-level connection records available in this report. Click a row
            to inspect connection details. Hover highlighted values to see the
            pivot control; click a highlighted value to filter the full report.
          </p>
          <label>
            <span>Filter flows</span>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="IP, service, state, subnet…"
            />
          </label>
        </div>
        <div className="zeek-flow-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Destination</th>
                <th>Service / Protocol</th>
                <th>State</th>
                <th>History</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {pageRows.map((row, index) => {
                const src = val(row, "src_endpoint.ip");
                const dst = val(row, "dst_endpoint.ip");
                const namedService =
                  val(row, "service.name") ||
                  val(row, "connection_info.protocol_name");
                const dstPort = val(row, "dst_endpoint.port");
                const service = namedService || `Port ${dstPort || "—"}`;
                return (
                  <tr
                    key={`${src}-${dst}-${start + index}`}
                    onClick={() =>
                      onSelect({
                        type: "connection",
                        id: `${src}|${dst}|${service}`,
                      })
                    }
                  >
                    <td>
                      {src ? (
                        <>
                          <PivotValue
                            filter={{ key: "ip", value: src, label: "Device" }}
                            filters={filters}
                            onFilter={onFilter}
                          >
                            {src}
                          </PivotValue>
                          {val(row, "src_endpoint.port") ? (
                            <>
                              :
                              <PivotValue
                                filter={{
                                  key: "port",
                                  value: val(row, "src_endpoint.port"),
                                  label: "Port",
                                }}
                                filters={filters}
                                onFilter={onFilter}
                              >
                                {val(row, "src_endpoint.port")}
                              </PivotValue>
                            </>
                          ) : null}
                        </>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      {dst ? (
                        <>
                          <PivotValue
                            filter={{ key: "ip", value: dst, label: "Device" }}
                            filters={filters}
                            onFilter={onFilter}
                          >
                            {dst}
                          </PivotValue>
                          {val(row, "dst_endpoint.port") ? (
                            <>
                              :
                              <PivotValue
                                filter={{
                                  key: "port",
                                  value: val(row, "dst_endpoint.port"),
                                  label: "Port",
                                }}
                                filters={filters}
                                onFilter={onFilter}
                              >
                                {val(row, "dst_endpoint.port")}
                              </PivotValue>
                            </>
                          ) : null}
                        </>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      {namedService ? (
                        <PivotValue
                          filter={{
                            key: "service",
                            value: namedService,
                            label: "Service",
                          }}
                          filters={filters}
                          onFilter={onFilter}
                        >
                          {namedService}
                        </PivotValue>
                      ) : dstPort ? (
                        <PivotValue
                          filter={{
                            key: "port",
                            value: dstPort,
                            label: "Port",
                          }}
                          filters={filters}
                          onFilter={onFilter}
                        >
                          Port {dstPort}
                        </PivotValue>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      {row.state ? (
                        <PivotValue
                          filter={{
                            key: "zeekState",
                            value: String(row.state),
                            label: "Zeek State",
                          }}
                          filters={filters}
                          onFilter={onFilter}
                        >
                          {String(row.state)}
                        </PivotValue>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>{row.history || "—"}</td>
                    <td>{row.success ? "Successful" : "Unsuccessful"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="zeek-flow-foot">
          <span>
            Showing {first.toLocaleString()}–{last.toLocaleString()} of{" "}
            {rows.length.toLocaleString()} matching flow records.
          </span>
          <div className="zeek-flow-pagination">
            <label>
              <span>Rows per page</span>
              <select
                value={pageSize}
                onChange={(event) => setPageSize(Number(event.target.value))}
              >
                <option value={10}>10</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </label>
            <button
              type="button"
              onClick={() => setPage((value) => Math.max(1, value - 1))}
              disabled={page <= 1}
            >
              Previous
            </button>
            <span className="zeek-flow-page">
              Page {page} of {totalPages}
            </span>
            <button
              type="button"
              onClick={() =>
                setPage((value) => Math.min(totalPages, value + 1))
              }
              disabled={page >= totalPages}
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </Panel>
  );
};

export default ZeekFlowAnalysis;
