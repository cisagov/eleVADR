# Topology Query Explorer — Wave 3

## Changes

- Query matching uses all report-derived relationship records, not the 180-edge display subset or the first 1,500 connection records.
- Rendering remains bounded to keep the visualization responsive; the results list shows the first 100 matches and the total count.
- MongoDB saved-query definitions remain scoped to the authenticated owner and reusable between reports.
- Added validation for empty string query values and unsafe query identifiers.
- Added regression tests for create/update/list/delete, owner isolation, invalid inputs, and report-independent query definitions.

## Validation

Run from the repository root:

```powershell
python -m unittest backend_bryan.tests.test_topology_query_wave3 -v
cd frontend
npm run type-check
npm run build
```

## Limitations

- Query execution is client-side over the relationships available in the loaded JSON report, not raw Zeek logs or a server-side graph database. Missing or pre-truncated report data cannot be queried.
- The visible graph is limited to a subset of edges; a query may match relationships not currently drawn.
- Full browser and live authenticated MongoDB integration testing remain to be done.
- Query builder supports structured filters, not arbitrary Cypher or multi-hop traversal.
