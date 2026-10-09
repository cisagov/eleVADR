# Wave 7 completion patch (current source checkout)

This patch was prepared against the user-provided `eleVADR-feature-ui-multi-user (1).zip`.

## Changes
- Recall a saved comparison from the owner-scoped `/api/v1/reports/{reportId}` endpoint when the current report matches. If the baseline is not retained, the UI explains that the analyst must reopen its JSON file. The active report is never replaced.
- Apply additional cross-report query filters (asset class, subnet, role, Purdue level, suspicious and finding-related, alongside existing service/count and bounded directional traversal). Class/role/Purdue information is limited to fields present in each report; unknown metadata remains unknown.
- Preserve the original comparison inspector, export, saved-query functionality, and visual overlays.

## Important limitations
- Automated restoration only works for baseline reports retained in the authenticated MongoDB report store. External JSON-only baselines still need manual selection.
- Report-derived device roles and Purdue classifications may be incomplete, so filters may differ from enriched current-graph context classifications.
- Full frontend type-check/build, browser end-to-end and live MongoDB integration were not run in this environment. Do not declare Wave 7 fully production-verified based on this patch alone.

## Apply
Extract over the repository root, preserving paths. Restart `backend_bryan` and Vite if needed.

## Validate on Windows
From `frontend`: `npm run type-check` and `npm run build`.
From repo root: `python -m unittest backend_bryan.tests.test_topology_comparison_wave7 -v`.
In browser: save a comparison using two retained reports, sign out/in, recall it; test a baseline that is not retained and confirm the manual-file fallback; run 1-4 hop queries on both reports with class, subnet, suspicious and findings filters; test a second user cannot access the saved comparison.
