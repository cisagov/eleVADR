@echo off
setlocal
set "ROOT=%~dp0"
cd /d "%ROOT%"

if "%~1"=="" (
  python -m backend_bryan.integration.release_candidate_gate --clean
) else (
  python -m backend_bryan.integration.release_candidate_gate %*
)
exit /b %ERRORLEVEL%
