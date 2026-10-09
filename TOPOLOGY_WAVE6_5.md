# eleVADR Topology Wave 6.5: Progressive Display and Layout Cache

Patch on top of Wave 6.4 (or Wave 6.3 plus the Wave 6.4 patch).

- Cache aggregate-cluster grid coordinates keyed by grouping mode and ordered cluster IDs; query panel changes do not require recomputing the coordinate grid.
- Add **Progressively show all** and **Pause progressive display** controls. Additional clusters appear in batches of 24 on animation frames. The existing manual 24-cluster button remains.
- Cancel scheduled frame work when display scope changes or the component unmounts.
- Add optional rendering diagnostics: visible cluster and edge counts plus the scheduling delay of the latest reveal. These are NOT browser paint or frame-rate benchmarks.
- Preserve full-report graph query scope; only rendered SVG groups are bounded.

## Windows validation

From `frontend`:

```powershell
npm run type-check
npm run build
```

Open a large report, select Group by Subnet, and try Progressive show all / Pause / Reset. Change query filters while rendering and confirm the graph remains interactive. The browser Performance panel can be used to record actual long tasks and paint times. This patch has not been browser-tested.
