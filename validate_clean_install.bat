@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo eleVADR clean-install validation
 echo ============================================================

python -m backend_bryan.integration.deployment_preflight --initialized
if errorlevel 1 exit /b 1

call check_elevadr_database.bat
if errorlevel 1 exit /b 1

pushd frontend
call npm.cmd run build
set "RC=%ERRORLEVEL%"
popd
if not "%RC%"=="0" exit /b %RC%

python -m backend_bryan.integration.release_preflight
if errorlevel 1 exit /b 1

call run_platform_regression_tests.bat
if errorlevel 1 exit /b 1

echo.
echo PASS: clean-install validation completed successfully.
echo Optional strongest validation: run_release_candidate_validation.bat --full
exit /b 0
