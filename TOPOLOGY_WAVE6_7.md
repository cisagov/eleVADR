# eleVADR Topology Wave 6.7 — Indexed progressive edges

Apply this patch over Wave 6.6. It replaces repeated O(E) scans on every cluster reveal with an indexed edge order and binary search. The index is recomputed only when the aggregated graph changes. The queryable graph and saved-query behavior are unchanged.

## Validation

Run `node frontend/scripts/benchmark-progressive-edge-selection.mjs` from the repository root. Then from `frontend`, run `npm run type-check` and `npm run build`.

The benchmark checks exact equality against the original filtering logic at 100 reveal thresholds for three synthetic sizes. Results are synthetic Node.js timings, not browser frame measurements.

## Browser benchmark status

The Wave 6.6 Chrome headless benchmark could not complete in this execution environment. No browser frame-rate improvement is claimed. Open `frontend/scripts/topology-browser-benchmark.html` in your local Chrome and run the benchmark to collect actual browser measurements.
