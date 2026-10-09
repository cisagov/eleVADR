# Wave 7: Cross-report topology comparison

Patch over Wave 6.8. In Topology choose **Compare with another report**, select a baseline JSON report, and inspect new/not-observed assets and changed directed communication relationships. Counts are derived from report panels and can reflect capture duration differences. The current report is never overwritten. No server upload is performed.

Validation on Windows: `cd frontend`, `npm run type-check`, `npm run build`.

Limitations: no cross-report persistence, query-on-diff, or full browser test. Report-derived relationships may omit evidence absent from source reports.
