# Stage 3 report persistence

Stage 3 persists completed authenticated PCAP analysis reports without changing the analysis engine. The report returned by the analyzer is first written atomically as JSON beneath `storage/users/<user-id>/reports/`; MongoDB stores only owner-scoped searchable metadata and the relative JSON path.

Endpoints (authentication required):

- `GET /api/v1/reports` lists the current user's reports.
- `GET /api/v1/reports/<report-id>` loads one current-user report.
- `DELETE /api/v1/reports/<report-id>` deletes its JSON and metadata.

Report and analysis-job lookups are owner scoped. Cross-user lookups return not-found behavior rather than disclosing another user's object. PCAP bytes are not retained by Stage 3; only the original source filename is indexed with the report. The `storage/` runtime directory is gitignored.
