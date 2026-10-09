# eleVADR Topology Wave 7.7–7.9

This is an **incremental patch** for the current working Wave 7.4–7.6 checkout, not a complete repository. Back up or commit the current working tree before applying.

## Installation (Windows PowerShell, repository root)

1. Extract the patch over the repository, retaining paths. **Do not overwrite your existing `backend_bryan/integration/http_reference_server.py` with an older file**; this patch intentionally ships a route installer instead.
2. Run `python apply_wave7_comparison_backend.py` once to add comparison routes to your existing backend server. It makes a `.wave7-backup` copy and refuses to apply if the expected topology query routes differ.
3. Restart eleVADR using your development launcher.
4. Run `python -m unittest backend_bryan.tests.test_topology_comparison_wave7 -v`.
5. From `frontend`, run `npm run type-check` and `npm run build`.

## Features

- MongoDB-backed saved comparison settings scoped by authenticated owner, with list/create/update/delete API under `/api/v1/topology-comparisons`. Requires write permission for changes.
- Saved settings reference report identifiers and filters; report JSON files are **not** stored by this feature. Reopen the original baseline JSON before recalling a comparison.
- Cross-report bounded 1–4 hop observed-communication traversal runs independently on baseline and current snapshots using the active query's starting IP, direction, depth, service and minimum observations. It displays newly matching and no-longer-matching relationship counts. These are *observations*, not proof of physical reachability.
- The existing current-report Graph Query Explorer retains its other asset and finding filters; these filters are **not yet applied identically to both reports** in the cross-report traversal.

## Validation and limitations

- Python unit tests use a mocked Mongo collection for owner isolation; they are not a live MongoDB integration test.
- The TSX file passed TypeScript's syntax transpiler. Full project type-check/build and browser interaction are still required in your Windows checkout.
- No automatic lookup of baseline report JSON is performed. This patch does not claim full end-to-end cross-report query parity or complete Wave 7.9 coverage.
- The backend uses in-memory job processing as before; no Zeek or authentication changes.
