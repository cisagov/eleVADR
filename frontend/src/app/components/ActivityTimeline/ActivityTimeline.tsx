import React, { useMemo, useState } from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ElevadrReport } from "../../types/Report";
import "./ActivityTimeline.css";

type TemporalPoint = { timestamp: number; label: string; source: string };
type Bucket = { time: string; events: number; suspicious: number };

const TIMESTAMP_KEYS = /(^|_)(timestamp|time|ts|datetime|date|start_time|end_time)$/i;
const MAX_SCAN_DEPTH = 7;
const MAX_POINTS = 8000;

function toTimestamp(value: unknown): number | null {
  if (typeof value === "number") {
    const ms = value > 1e12 ? value : value > 1e9 ? value * 1000 : NaN;
    return Number.isFinite(ms) ? ms : null;
  }
  if (typeof value !== "string" || value.length < 8) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function collectTemporalPoints(value: unknown, points: TemporalPoint[], path = "report", depth = 0): void {
  if (depth > MAX_SCAN_DEPTH || points.length >= MAX_POINTS || value == null) return;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length && points.length < MAX_POINTS; i += 1) {
      collectTemporalPoints(value[i], points, `${path}[${i}]`, depth + 1);
    }
    return;
  }
  if (typeof value !== "object") return;
  const record = value as Record<string, unknown>;
  for (const [key, field] of Object.entries(record)) {
    if (TIMESTAMP_KEYS.test(key)) {
      const timestamp = toTimestamp(field);
      if (timestamp) points.push({ timestamp, label: key, source: path });
    }
  }
  for (const [key, field] of Object.entries(record)) {
    if (typeof field === "object" && field !== null) collectTemporalPoints(field, points, `${path}.${key}`, depth + 1);
  }
}

function bucketize(points: TemporalPoint[], bucketCount: number): Bucket[] {
  if (points.length < 2) return [];
  const sorted = [...points].sort((a, b) => a.timestamp - b.timestamp);
  const start = sorted[0].timestamp;
  const end = sorted[sorted.length - 1].timestamp;
  const range = Math.max(1, end - start);
  const size = range / bucketCount;
  const buckets = Array.from({ length: bucketCount }, (_, index) => ({
    time: new Date(start + size * index).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }),
    events: 0,
    suspicious: 0,
  }));
  for (const point of sorted) {
    const index = Math.min(bucketCount - 1, Math.floor((point.timestamp - start) / size));
    buckets[index].events += 1;
    if (/suspicious|risk|alert|anomal/i.test(point.source)) buckets[index].suspicious += 1;
  }
  return buckets;
}

const ActivityTimeline: React.FC<{ report: ElevadrReport }> = ({ report }) => {
  const [granularity, setGranularity] = useState(24);
  const temporalPoints = useMemo(() => {
    const points: TemporalPoint[] = [];
    collectTemporalPoints(report, points);
    return points;
  }, [report]);
  const data = useMemo(() => bucketize(temporalPoints, granularity), [temporalPoints, granularity]);
  const range = useMemo(() => {
    if (!temporalPoints.length) return null;
    const values = temporalPoints.map((point) => point.timestamp);
    return { start: new Date(Math.min(...values)), end: new Date(Math.max(...values)) };
  }, [temporalPoints]);

  return (
    <section className="activity-timeline" aria-label="Activity timeline visualization">
      {data.length > 0 && (
        <div className="activity-timeline-controls">
          <label><span>Resolution</span><select value={granularity} onChange={(event) => setGranularity(Number(event.target.value))}><option value={12}>12 buckets</option><option value={24}>24 buckets</option><option value={48}>48 buckets</option></select></label>
        </div>
      )}
      {data.length > 0 ? (
        <div className="activity-timeline-chart">
          <ResponsiveContainer width="100%" height={285}>
            <AreaChart data={data} margin={{ top: 12, right: 24, left: 0, bottom: 8 }}>
              <defs><linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#0b6e99" stopOpacity={0.28}/><stop offset="95%" stopColor="#0b6e99" stopOpacity={0.02}/></linearGradient></defs>
              <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#dfe8ee" />
              <XAxis dataKey="time" tick={{ fontSize: 10 }} minTickGap={36} axisLine={false} tickLine={false} />
              <YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{ fontSize: 11 }} />
              <Tooltip />
              <Area type="monotone" dataKey="events" name="Timestamped observations" stroke="#0b6e99" strokeWidth={2} fill="url(#activityFill)" />
              <Area type="monotone" dataKey="suspicious" name="Suspicious/risk observations" stroke="#b65349" strokeWidth={2} fill="none" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <div className="timeline-empty"><strong>No temporal series available</strong><span>eleVADR will automatically render this chart when timestamp/date fields are present in a report. Current network evidence remains available in the connection and topology views.</span></div>
      )}
    </section>
  );
};
export default ActivityTimeline;
