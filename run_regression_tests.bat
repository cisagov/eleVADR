@echo off
setlocal
set "ROOT=%~dp0"
cd /d "%ROOT%"

rem Allow Node helpers launched by pytest to resolve frontend-local dependencies.
set "NODE_PATH=%ROOT%frontend\node_modules;%NODE_PATH%"

echo ============================================================
echo eleVADR regression gate
echo ============================================================
echo.

echo [1/26] Release-readiness preflight
python -m backend_bryan.integration.release_preflight
if errorlevel 1 goto :fail

echo.
echo [2/26] Backend unit/regression tests
python -m pytest backend_bryan\tests
if errorlevel 1 goto :fail

echo.
echo [3/26] Live PCAP regression pack ^(legacy 60-detector baseline^)
python -m backend_bryan.regression.runner --mode live
if errorlevel 1 goto :fail

echo.
echo [4/26] Dataset 04 control/discovery semantics
python -m backend_bryan.regression.dataset04_runner
if errorlevel 1 goto :fail

echo.
echo [5/26] Dataset 05 parser/malformed-evidence robustness
python -m backend_bryan.regression.dataset05_runner
if errorlevel 1 goto :fail

echo.
echo [6/26] Dataset 06 detector threshold/boundary semantics
python -m backend_bryan.regression.dataset06_runner
if errorlevel 1 goto :fail

echo.
echo [7/26] Dataset 07 temporal/state-isolation semantics
python -m backend_bryan.regression.dataset07_runner
if errorlevel 1 goto :fail

echo.
echo [8/26] Dataset 08 policy-precedence/conflict semantics
python -m backend_bryan.regression.dataset08_runner
if errorlevel 1 goto :fail

echo.
echo [9/26] Dataset 09 report determinism/reproducibility
python -m backend_bryan.regression.dataset09_runner
if errorlevel 1 goto :fail

echo.
echo [10/26] Dataset 10 performance/scale behavior
python -m backend_bryan.regression.dataset10_runner
if errorlevel 1 goto :fail

echo.
echo [11/26] Dataset 11 failure-recovery/cancellation semantics
python -m backend_bryan.regression.dataset11_runner
if errorlevel 1 goto :fail

echo.
echo [12/26] Dataset 12 input/security hardening
python -m backend_bryan.regression.dataset12_runner
if errorlevel 1 goto :fail

echo.
echo [13/26] Dataset 13 UI workflow resilience
python -m backend_bryan.regression.dataset13_runner
if errorlevel 1 goto :fail

echo.
echo [14/26] Dataset 20 topology interaction regression contract
python -m backend_bryan.regression.dataset20_runner
if errorlevel 1 goto :fail

echo.
echo [15/26] Dataset 14 mixed OT acceptance scenario
python -m backend_bryan.regression.dataset14_runner
if errorlevel 1 goto :fail

echo.
echo [16/26] Wave 1 detector acceptance ^(75-module registry^)
python -m backend_bryan.regression.new_detector_acceptance_runner
if errorlevel 1 goto :fail

echo.
echo [17/26] Wave 2 detector acceptance ^(75-module registry^)
python -m backend_bryan.regression.wave2_detector_acceptance_runner
if errorlevel 1 goto :fail

echo.
echo [18/26] Wave 3 detector acceptance ^(75-module registry^)
python -m backend_bryan.regression.wave3_detector_acceptance_runner
if errorlevel 1 goto :fail

echo [19/26] Dataset 15 raw-PCAP validation for five Wave 1 detectors
python -m backend_bryan.regression.dataset15_runner
if errorlevel 1 goto :fail

echo.
echo [20/26] Dataset 16 raw-PCAP validation for five Wave 2 detectors
python -m backend_bryan.regression.dataset16_runner
if errorlevel 1 goto :fail

echo.
echo [21/26] Dataset 17 raw-PCAP validation for five Wave 3 detectors
python -m backend_bryan.regression.dataset17_runner
if errorlevel 1 goto :fail

echo.
echo [22/26] Dataset 19 four-hour site-like OT false-positive tripwire
python -m backend_bryan.regression.dataset19_runner
if errorlevel 1 goto :fail

echo.
echo [23/26] Frontend TS/TSX transpilation validation
node backend_bryan\regression\validate_frontend_ts.cjs
if errorlevel 1 goto :fail

echo.
echo [24/26] Network topology interaction component tests
pushd frontend
call npm test -- src/tests/NetworkTopologyInteraction.test.tsx
set "TOPOLOGY_TEST_RC=%ERRORLEVEL%"
popd
if not "%TOPOLOGY_TEST_RC%"=="0" goto :fail

echo.
echo [25/26] Report compatibility contract
node backend_bryan\regression\validate_report_compatibility.cjs
if errorlevel 1 goto :fail

echo.
echo [26/26] Findings explainability UX contract
node backend_bryan\regression\validate_findings_explainability.cjs
if errorlevel 1 goto :fail

echo.
echo ============================================================
echo PASS: eleVADR regression gate completed successfully.
echo ============================================================
exit /b 0

:fail
echo.
echo ============================================================
echo FAIL: eleVADR regression gate stopped on an error.
echo ============================================================
exit /b 1
