import React, { useRef } from "react";
import Panel from "./Panel/Panel";
import PivotValue from "./PivotValue/PivotValue";
import { InvestigationFilter } from "../types/Investigation";
import "./SupplementalSubnetPanel.css";

export type SupplementalSubnet = {
  subnet: string;
  label: string;
  classification: string;
  notes: string;
};
interface Props {
  rows: SupplementalSubnet[];
  filters: InvestigationFilter[];
  onChange: (rows: SupplementalSubnet[]) => void;
  onFilter: (filter: InvestigationFilter) => void;
}
const parseCsv = (text: string) => {
  const lines = text.split(/\r?\n/).filter(Boolean);
  if (!lines.length) return [];
  const headers = lines[0].split(",").map((x) => x.trim().toLowerCase());
  return lines.slice(1).map((line) => {
    const cells = line.split(",").map((x) => x.trim());
    const obj: Record<string, string> = {};
    headers.forEach((h, i) => (obj[h] = cells[i] || ""));
    return obj;
  });
};
const SupplementalSubnetPanel: React.FC<Props> = ({
  rows,
  filters,
  onChange,
  onFilter,
}) => {
  const input = useRef<HTMLInputElement>(null);
  const load = async (file?: File) => {
    if (!file) return;
    const text = await file.text();
    try {
      const parsed: unknown = file.name.toLowerCase().endsWith(".json")
        ? JSON.parse(text)
        : parseCsv(text);
      const parsedRecord =
        parsed && typeof parsed === "object"
          ? (parsed as Record<string, unknown>)
          : {};
      const candidates = Array.isArray(parsed)
        ? parsed
        : Array.isArray(parsedRecord.subnets)
          ? parsedRecord.subnets
          : [];
      const normalized = candidates
        .filter(
          (x): x is Record<string, unknown> =>
            x !== null && typeof x === "object" && !Array.isArray(x),
        )
        .map((x) => ({
          subnet: String(x.subnet || x.cidr || ""),
          label: String(x.label || x.name || ""),
          classification: String(
            x.classification || x.class || x.type || "Unclassified",
          ),
          notes: String(x.notes || x.description || ""),
        }))
        .filter((x: SupplementalSubnet) => x.subnet);
      onChange(normalized);
    } catch {
      onChange([]);
    }
  };
  return (
    <Panel id="supplemental-subnet-data" title="Supplemental Subnet Data">
      <div className="supplemental-subnets">
        <div className="supplemental-toolbar">
          <p>
            Import analyst-provided subnet labels and classifications. Click a
            subnet value to filter the full report.
          </p>
          <div className="supplemental-actions">
            <input
              ref={input}
              type="file"
              accept=".csv,.json"
              onChange={(e) => void load(e.target.files?.[0])}
            />
            <button type="button" onClick={() => input.current?.click()}>
              Choose Subnet File
            </button>
            {rows.length > 0 && (
              <button type="button" onClick={() => onChange([])}>
                Clear
              </button>
            )}
          </div>
        </div>
        {rows.length > 0 ? (
          <div className="supplemental-table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Subnet</th>
                  <th>Label</th>
                  <th>Classification</th>
                  <th>Notes</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row, index) => (
                  <tr key={`${row.subnet}-${index}`}>
                    <td>
                      <PivotValue
                        filter={{
                          key: "subnet",
                          value: row.subnet,
                          label: "Subnet",
                        }}
                        filters={filters}
                        onFilter={onFilter}
                      >
                        {row.subnet}
                      </PivotValue>
                    </td>
                    <td>{row.label || "â€”"}</td>
                    <td>{row.classification}</td>
                    <td>{row.notes || "â€”"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="supplemental-empty">
            No supplemental subnet data loaded. Supported formats: CSV or JSON.
          </p>
        )}
      </div>
    </Panel>
  );
};
export default SupplementalSubnetPanel;
