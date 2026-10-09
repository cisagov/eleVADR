# Topology Query Explorer — Wave 2

The Topology panel includes a structured Graph Query Explorer with templates, asset class, subnet, Purdue level, service, minimum observation count, suspicious and finding-related conditions. **Run query** highlights matching edges and assets and displays the first 100 matching relationships. It queries the report-derived topology graph, currently capped at 180 relationships by the existing visualization data pipeline. It does not query raw Zeek logs, support arbitrary Cypher, or compare reports yet.

Authenticated users can load named queries from MongoDB, save/update their own queries, and delete their own queries. Query definitions are user-scoped and reusable on another report. Analyst/admin users can write; viewer accounts may read saved queries but cannot modify them. The backend routes are `GET/POST /api/v1/topology-queries` and `DELETE /api/v1/topology-queries/{id}`. No arbitrary MongoDB queries are accepted.

## Installation and verification

Use the complete source ZIP, retaining your local `.elevadr-platform.env`. Restart `backend_bryan` with `start_elevadr.bat` so the MongoDB collection and new routes initialize. Check frontend with `npm run type-check`, `npm run build`, and browser testing. With a report loaded, open Topology > Graph Query Explorer, select a template, run it, save it, switch reports, and recall it. Confirm a second account cannot read the first account's saved queries.

## Known limitations

Frontend compilation/browser tests and MongoDB integration tests were not run in this environment. Existing topology graph data truncation can omit relationships. The structured query builder is deliberately bounded; Cypher text execution and cross-report traversal are future waves.
