/**
 * Dependency-free synthetic benchmark for the aggregate topology data pipeline.
 * Run: node scripts/benchmark-topology.mjs
 * This measures graph preparation, NOT React/SVG layout or browser frame rate.
 */
import { performance } from 'node:perf_hooks';
import assert from 'node:assert/strict';

function buildGraph(nodeCount, edgeCount) {
  const nodes = Array.from({ length: nodeCount }, (_, id) => ({ id: `10.0.${Math.floor(id / 256)}.${id % 256}`, group: `segment-${id % 128}` }));
  const edges = Array.from({ length: edgeCount }, (_, i) => ({
    source: nodes[(i * 37) % nodeCount].id,
    target: nodes[(i * 97 + 17) % nodeCount].id,
    count: (i % 50) + 1,
    service: ['modbus', 'dnp3', 'http', 'dns'][i % 4],
  }));
  return { nodes, edges };
}
function aggregate(nodes, edges) {
  const groups = new Map();
  for (const node of nodes) groups.set(node.id, node.group);
  const result = new Map();
  for (const edge of edges) {
    const source = groups.get(edge.source), target = groups.get(edge.target);
    if (!source || !target || source === target) continue;
    const key = JSON.stringify([source, target]);
    let item = result.get(key);
    if (!item) result.set(key, item = { source, target, observations: 0, relationships: 0, services: new Set() });
    item.observations += edge.count;
    item.relationships++;
    item.services.add(edge.service);
  }
  return result;
}

for (const [nodeCount, edgeCount] of [[1000, 10000], [5000, 100000], [10000, 250000]]) {
  const { nodes, edges } = buildGraph(nodeCount, edgeCount);
  const start = performance.now();
  const result = aggregate(nodes, edges);
  const elapsed = performance.now() - start;
  const total = [...result.values()].reduce((sum, edge) => sum + edge.relationships, 0);
  assert(total > 0 && total <= edgeCount);
  assert([...result.values()].every((edge) => edge.observations > 0));
  console.log(`${nodeCount} nodes, ${edgeCount} relationships: ${elapsed.toFixed(1)} ms; ${result.size} aggregate edges; ${total} cross-group relationships`);
}
