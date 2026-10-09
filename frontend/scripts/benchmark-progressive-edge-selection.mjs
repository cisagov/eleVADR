import { performance } from 'node:perf_hooks';
const cases = [[100, 1000], [1000, 50000], [5000, 250000]];
function generate(n, m) {
  let state = 123456789;
  const rand = () => ((state = (Math.imul(state, 1664525) + 1013904223) >>> 0) / 4294967296);
  return Array.from({ length: m }, () => ({ source: Math.floor(rand() * n), target: Math.floor(rand() * n) }));
}
for (const [nodes, count] of cases) {
  const edges = generate(nodes, count);
  const sorted = edges.map(edge => ({ edge, revealAt: Math.max(edge.source, edge.target) })).sort((a,b) => a.revealAt - b.revealAt);
  const limits = Array.from({length: 100}, (_, i) => Math.max(1, Math.floor((i + 1) * nodes / 100)));
  const t0 = performance.now();
  const baseline = limits.map(limit => edges.filter(e => e.source < limit && e.target < limit).length);
  const t1 = performance.now();
  const optimized = limits.map(limit => {
    let low = 0, high = sorted.length;
    while (low < high) { const mid = (low + high) >>> 1; if (sorted[mid].revealAt < limit) low = mid + 1; else high = mid; }
    return low;
  });
  const t2 = performance.now();
  if (baseline.some((value,i) => value !== optimized[i])) throw Error('Edge counts disagree');
  console.log(`${nodes} clusters, ${count} edges: 100 reveals: scan ${(t1-t0).toFixed(1)}ms; indexed ${(t2-t1).toFixed(1)}ms; identical counts PASS`);
}
