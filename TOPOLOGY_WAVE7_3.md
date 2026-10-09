# Wave 7.3 - Selectable comparison relationships

- Select a changed relationship from the comparison results list or by clicking a highlighted edge in the graph.
- Inspect baseline/current observation counts, change delta, endpoints, and service.
- Inspect endpoint assets using the existing report selection action. Baseline-only assets may not exist in the current report.
- Enter and Space activate overlay edges. Close clears selection; clearing the comparison clears selection.
- No Zeek reprocessing or database changes.

## Verify

From frontend: `npm run type-check` and `npm run build`. Then load a current report and baseline report and test both regular and grouped topology overlays.
