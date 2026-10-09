# Wave 6.6 — Adaptive progressive display and browser workload benchmark

Apply this patch over Wave 6.5. It retains the existing graph query engine and cluster inspection.

- Progressive reveal adapts from 24 to 12 or 6 clusters when the previous animation-frame scheduling delay is high (over 24 or 48 ms). Manual reveal remains 24 clusters.
- `frontend/scripts/topology-browser-benchmark.html` is a standalone browser benchmark of synthetic SVG nodes/edges. Open it in Chrome, click Run benchmark, and compare measurements on the same machine across changes.
- The benchmark is **not** a measurement of React topology rendering, real graph layout, or end-to-end eleVADR performance. The two-frame value is only a paint scheduling proxy.

## Validation

From `frontend`: `npm run type-check` and `npm run build`.
Then open `scripts/topology-browser-benchmark.html` in Chrome and record results. Test progressive display in the real Topology workspace separately.
