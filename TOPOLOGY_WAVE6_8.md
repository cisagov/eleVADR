# Wave 6.8 - Browser Performance Validation

This patch adds opt-in browser frame interval and Long Task API measurements to the actual eleVADR Topology component. It does not change query semantics, cluster aggregation, saved queries, or authentication.

## Use
1. Apply over Wave 6.7.
2. Run `npm run type-check` and `npm run build` from `frontend`.
3. Load a large report and choose a grouping mode.
4. Open **Rendering diagnostics**. Wait at least two seconds for the first 120-frame sample.
5. Record mean and p95 frame intervals, >50 ms frames, long-task count, and longest long task. Repeat after expanding/collapsing a cluster, running a query, and enabling progressive reveal.
6. Repeat with diagnostics disabled to assess measurement overhead.

These are real browser scheduling measurements, but they do **not** isolate React commit duration, layout computation, or paint time. Long Task API support varies by browser. For those breakdowns, use Chrome Performance and React Profiler. Avoid treating the frame interval as a direct render duration.

## Suggested regression scenarios
- 100 assets / 500 links
- 1,000 assets / 10,000 links
- 5,000 assets / 100,000 links
- 10,000 assets / 250,000 links

Use report data that genuinely contains these counts; the graph visualization is capped and the source report may contain fewer relationships. Check that queries still cover all report-derived relationships and progressive display only limits rendered clusters.

## Validation limitations
No real-browser measurements have been collected in this environment. TypeScript compilation requires dependencies and a compatible Node version in the user's frontend installation. This patch intentionally does not claim an unmeasured speedup.
