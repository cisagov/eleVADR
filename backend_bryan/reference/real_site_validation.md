# Real-site PCAP validation workflow

Use this workflow after the synthetic and raw-PCAP regression gates are green. It is designed to answer three questions: what eleVADR detects on representative traffic, what it misses, and which findings are useful versus noisy.

1. Select a representative, appropriately sanitized site PCAP and create a matching Detection Context from independently known site information. Do not build authorization by copying what the capture happens to contain.
2. Run `run_real_site_validation.bat <pcap> <context.json> <output-dir>` from the repository root.
3. Review `coverage_summary.json` for Zeek log coverage, detector completion/errors, observed services, and modules with/without findings.
4. Review every row in `finding_review.csv`. Use `expected`, `useful-noisy`, `false-positive`, `uncertain`, or `not-applicable` as appropriate. Add notes explaining the site fact that supports the disposition.
5. Record expected-but-absent detections in `missed_detection_review.csv` so false negatives are not hidden by the finding-only worksheet.
6. Summarize the completed finding review with `python -m backend_bryan.regression.dataset18_real_site_runner --summarize-review <finding_review.csv> --output-dir <output-dir>`.
7. For each proposed detector change, add a focused regression case before changing thresholds or policy mapping. Prefer detector/evidence fixes over broad allowlists. Re-run the standard regression gate after every tuning change.

The generated artifacts may contain site IP addresses, hostnames, services, and other operational details. Handle them according to the environment's data-handling requirements; they are not included automatically in release ZIPs.
