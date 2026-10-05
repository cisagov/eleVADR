# Real-data analysis workflow

The local development path now supports real Zeek rows end to end:

1. The browser scans `.log`, `.json`, and `.jsonl` Zeek files.
2. Scanner-derived profile facts are merged into Detection Context as before.
3. Parsed rows for supported Zeek log types are retained **in memory only** as analysis data. They are not stored as site policy and are not promoted to authorization.
4. **Analyze Zeek Data** sends the normalized Detection Context v3 profile plus those parsed rows in `DetectionAnalysisRequest v1`.
5. `backend_bryan` validates the request, compiles the profile to detector metadata, builds `AnalysisContext`, executes the selected modules, and returns `DetectionAnalysisResponse v1`.
6. The frontend **Analysis Results** section displays module completion, modules with findings, total findings, failed modules, and expandable detector findings.

## Supported log handoff

The scanner forwards only API-supported Zeek log names. `conn.log` is normalized to `connections`; unsupported log filenames may still contribute scanner evidence but are not sent to the detector API.

## Golden fixtures

`reference/e2e/rogue_finding_request.json` contains a known private host that is absent from the asset inventory and must produce one `unknown_rogue_devices` finding.

`reference/e2e/rogue_suppressed_request.json` adds that host to the explicit asset inventory and must produce zero findings. These fixtures verify that actual Zeek analysis data and explicit Detection Context policy interact as intended.

## Analyst-facing results view

The frontend Analysis Results view now presents detector output for investigation rather than raw module debugging. It includes:

- friendly detector titles with the stable module id shown as secondary text;
- severity badges and severity-first ordering;
- filtering by severity, detector, and host/IP evidence;
- an optional view of detector modules that returned no findings;
- compact evidence summaries with expandable full detector evidence;
- links back to relevant Detection Context sections where a finding can be reviewed against site policy;
- JSON export of the complete versioned analysis response.

The frontend does not reinterpret detector policy. These controls only present the response returned by the analysis API.
