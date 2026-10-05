import React, { useEffect, useMemo, useState } from "react";
import { ElevadrReport } from "../../types/Report";
import "./RawJsonDrawer.css";

const RawJsonDrawer: React.FC<{ report: ElevadrReport; isOpen: boolean; onClose: () => void }> = ({ report, isOpen, onClose }) => {
  const [filter, setFilter] = useState("");
  const [copied, setCopied] = useState(false);
  const json = useMemo(() => JSON.stringify(report, null, 2), [report]);

  useEffect(() => {
    if (!isOpen) return;
    const listener = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    window.addEventListener("keydown", listener);
    return () => window.removeEventListener("keydown", listener);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const lines = json.split("\n");
  const normalized = filter.trim().toLowerCase();
  const visible = normalized ? lines.filter((line) => line.toLowerCase().includes(normalized)) : lines;

  const copy = async () => {
    await navigator.clipboard.writeText(json);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1400);
  };

  return (
    <div className="json-drawer-layer" role="presentation">
      <button className="json-drawer-backdrop" aria-label="Close JSON viewer" onClick={onClose} />
      <aside className="json-drawer" role="dialog" aria-modal="true" aria-label="Raw report JSON">
        <header>
          <div><p>Source data</p><h2>Raw report JSON</h2></div>
          <button type="button" className="json-close" onClick={onClose} aria-label="Close JSON viewer">×</button>
        </header>
        <div className="json-tools">
          <input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter JSON lines…" />
          <button type="button" onClick={copy}>{copied ? "Copied" : "Copy JSON"}</button>
        </div>
        <div className="json-meta">{visible.length.toLocaleString()} of {lines.length.toLocaleString()} lines</div>
        <pre>{visible.join("\n")}</pre>
      </aside>
    </div>
  );
};

export default RawJsonDrawer;
