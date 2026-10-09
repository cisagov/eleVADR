# Topology Wave 6.4 - Aggregate preparation performance

This incremental update builds on Wave 6.3 and keeps the existing cluster drill-down and query UI unchanged.

## Changes

- Index cluster positions by cluster key once per graph change, rather than repeatedly searching clusters for every rendered aggregated edge.
- Reuse a memoized asset-to-cluster lookup when inspecting aggregated communications.
- Construct cluster membership without a temporary `flatMap` allocation.
- Add `frontend/scripts/benchmark-topology.mjs`, a dependency-free synthetic graph aggregation benchmark.

## Testing

From `frontend`:

```powershell
node scripts/benchmark-topology.mjs
npm run type-check
npm run build
```

In the application, check that grouping, expanding/collapsing clusters, aggregate edge inspection, saved queries, and right-panel expansion still work.

The benchmark measures only synthetic graph aggregation in Node. It is not a browser frame-rate benchmark, does not use real report data, and is not a guarantee of UI responsiveness. No backend, authentication, or database files were changed.
