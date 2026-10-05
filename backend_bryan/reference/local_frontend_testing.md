# Local frontend + backend_bryan testing

This workflow keeps the normal eleVADR frontend command unchanged while making
the isolated Detection Analysis reference service opt-in.

## 1. Configure the frontend once

From `eleVADR/frontend`, copy `.env.example` to `.env.local`:

```powershell
Copy-Item .env.example .env.local
```

The supplied example contains:

```text
VITE_DETECTION_ANALYSIS_URL=http://127.0.0.1:8765/api/v1/detection-analysis
```

Vite reads `.env.local` when the frontend starts. Restart the frontend after
changing the file. Do not commit `.env.local`.

If the variable is absent or blank, the frontend falls back to the same-origin
production-friendly path `/api/v1/detection-analysis`.

## 2. Start the frontend normally

```powershell
cd "C:\Users\BECKBR\OneDrive - Idaho National Laboratory\Desktop\eleVADR\frontend"
pnpm.cmd start --host 127.0.0.1
```

No new frontend command is required.

## 3. Start both parts with the bundled launcher

The generated project ZIP includes the detector package under `backend_bryan/vendor/elevadr_modules/`. No separate `pip install` or manual `PYTHONPATH` setup is required.

From the eleVADR repository root, double-click `start_elevadr.bat` or run:

```powershell
.\start_elevadr.bat
```

The launcher adds both the project root and the bundled detector package to `PYTHONPATH`, then starts `backend_bryan` and the frontend in separate consoles.

If you want to start only the reference backend manually, use:

```powershell
$env:PYTHONPATH = ".;.\backend_bryan\vendor"
python -m backend_bryan.integration.http_reference_server --host 127.0.0.1 --port 8765
```

The server prints:

```text
Listening on http://127.0.0.1:8765/api/v1/detection-analysis
```

The reference server includes permissive CORS headers solely for local contract
testing. This is not a production CORS policy and should not be copied into the
real backend without review.

## 4. Switch back to frontend-only development

Stop the reference server and either remove `.env.local` or leave the URL in
place. The frontend itself continues to start normally. Calls to the analysis
service will only succeed while the reference server is running.

For a same-origin production deployment, omit `VITE_DETECTION_ANALYSIS_URL` and
allow the frontend client to use `/api/v1/detection-analysis`.

## Verify the browser-to-backend_bryan path

After both consoles are running, open **Detection Context** in the frontend and click **Test Analysis API** in the footer.

The button sends the current normalized Detection Context v3 profile through the real `DetectionAnalysisRequest v1` client to the URL configured in `frontend/.env.local`.

A successful full-path test reports a message similar to:

```text
Analysis API connected · 70/75 modules completed · 0 finding(s).
```

The exact finding count depends on the profile and any analysis logs supplied. A `partial` result means the browser reached the API but one or more detector modules failed. A message beginning with `Analysis API test failed` means the browser could not complete the HTTP/contract exchange.

The generated ZIP already bundles `elevadr_modules`, and `start_elevadr.bat` adds it to Python's import path automatically. **Test Analysis API** remains the definitive local end-to-end check.

## Startup verification

The hardened local launcher stops any stale process already listening on port 8765 before starting `backend_bryan`.

The backend console must show lines similar to:

```text
Detector package: ...\backend_bryan\vendor\elevadr_modules\__init__.py
Detector modules: 75
Listening on http://127.0.0.1:8765/api/v1/detection-analysis
```

If `Detector modules: 75` is not shown, do not use the Test Analysis API button yet; the expected server is not the process currently running on port 8765.

## PCAP -> generated JSON report

With both processes running, select a PCAP/PCAPNG on the welcome screen. Choose a saved Detection Context profile (or open Detection Context first), then click **Analyze PCAP**. The frontend calls `VITE_PCAP_ANALYSIS_URL` and loads the returned v2 report through the same report loader used for an uploaded JSON report.

Local `.env.local` should contain:

```text
VITE_PCAP_ANALYSIS_URL=http://127.0.0.1:8765/api/v1/pcap-analysis
```

PCAP discovery and analysis require a Zeek runtime. `backend_bryan` first uses `ELEVADR_ZEEK_COMMAND` when set, then native `zeek` on PATH, then Docker Desktop with the pinned official image `zeek/zeek:9.0.0`. On Windows, start Docker Desktop before PCAP work when native Zeek is not installed. `prepare_zeek_runtime.bat` can pre-pull the Docker image; otherwise Docker pulls it automatically on first use.
