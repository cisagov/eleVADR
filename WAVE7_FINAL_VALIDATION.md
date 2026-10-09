# Wave 7 completion gate

This patch strengthens automated regression coverage for saved comparison settings. It does **not** certify full Wave 7 completion.

## Verified locally
- Owner-scoped create/list/update/delete behavior using an in-memory MongoDB collection double.
- Same saved comparison ID under different users does not collide.
- Invalid fields, types, filters, and IDs are rejected.
- Saved settings contain report IDs, not report payloads.

## Remaining required before closing Wave 7
1. Live MongoDB integration with authentication enabled, including sign-out/sign-in and cross-browser recall.
2. Browser E2E tests for baseline upload, comparison overlay, inspector, CSV/JSON export, saved comparison selection, and report switching.
3. Full query-filter parity across baseline and current reports: asset class, subnet, Purdue level, role group, suspicious and finding-related conditions. Current code only applies service/minimum count and bounded traversal to both snapshots.
4. Reopening the baseline JSON remains necessary. Implement durable baseline report lookup by owner-scoped report ID if automatic restore is required.
5. Validate npm run type-check and npm run build in the user's current checkout, then run the full regression suite.

## Apply
Copy backend_bryan/tests/test_topology_comparison_wave7.py into your working repository, retaining paths. This test-only patch does not replace the already-working frontend or backend routes.

## Run
python -m unittest backend_bryan.tests.test_topology_comparison_wave7 -v
