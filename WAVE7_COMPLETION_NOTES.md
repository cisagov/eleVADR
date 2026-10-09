# eleVADR Wave 7.4-7.6 integration patch

Apply over Wave 7.3. Contains only the updated NetworkTopology.tsx.

## Implemented
- Wave 7.4: Endpoint-associated detector finding counts and names in comparison inspector; optional filter for finding-associated communication changes. Associations are indicative, not definitive flow-level attribution.
- Wave 7.5: CSV/JSON comparison export, and named comparison settings stored in browser localStorage, scoped by current report ID. Baseline report files are not persisted; reopen the baseline JSON to reproduce a comparison.
- Wave 7.6 (initial): Apply the active Graph Query Explorer's service, starting-asset and minimum-observation filters to the comparison change list. Full multi-hop comparison traversal is not implemented.

## Known limitations
- Saved comparison settings are browser-local, not MongoDB-backed and not shared between devices or users. Browser-local settings are scoped by report ID, not authenticated user; do not use shared browser profiles for sensitive saved settings.
- Exports include all comparison changes (not just current filtered page).
- Finding association is based on reported asset or flow endpoint references; it does not prove a finding pertains to a particular service or edge.
- Query comparison filtering is not a full cross-report execution of the multi-hop query engine.
- Browser and TypeScript type-check tests are still required on the installed Windows frontend.

## Test
From frontend directory:
```
npm run type-check
npm run build
```
Then load a current report, open Topology comparison, select a baseline JSON, inspect finding associations, export CSV/JSON, save settings, reopen the panel and recall them, and apply a service-specific active graph query.
