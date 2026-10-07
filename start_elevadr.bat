@echo off
setlocal

set "ROOT=%~dp0"
set "ZEEK_IMAGE=zeek/zeek:9.0.0"

if defined ELEVADR_ZEEK_DOCKER_IMAGE set "ZEEK_IMAGE=%ELEVADR_ZEEK_DOCKER_IMAGE%"

if exist "%ROOT%.elevadr-platform.env" (
  echo Platform configuration: .elevadr-platform.env will be loaded by the backend.
) else (
  echo Platform configuration: not present; backend will use process/default settings.
)

echo Checking for an old eleVADR backend on port 8765...
for /f "tokens=5" %%P in ('netstat -ano ^| findstr /R /C:":8765 .*LISTENING"') do (
  echo Stopping stale process %%P on port 8765...
  taskkill /PID %%P /T /F >nul 2>&1
)

echo.
echo Checking Zeek runtime...
if defined ELEVADR_ZEEK_COMMAND (
  echo Zeek: explicit command ^(%ELEVADR_ZEEK_COMMAND%^)
) else (
  where zeek >nul 2>&1
  if not errorlevel 1 (
    for /f "delims=" %%Z in ('where zeek') do echo Zeek: native ^(%%Z^)
  ) else (
    where docker >nul 2>&1
    if not errorlevel 1 (
      echo Zeek: Docker fallback ^(%ZEEK_IMAGE%^)
      docker info >nul 2>&1
      if errorlevel 1 (
        echo WARNING: Docker is installed but Docker Desktop/Engine is not running.
        echo          Start Docker Desktop before PCAP context discovery or analysis.
      ) else (
        echo Docker is running. The Zeek image will be pulled automatically on first use if needed.
      )
    ) else (
      echo WARNING: No Zeek runtime was found.
      echo          Install/start Docker Desktop, install native Zeek, or set ELEVADR_ZEEK_COMMAND.
      echo          JSON report viewing will still work, but PCAP discovery/analysis will not.
    )
  )
)

echo.
echo Starting eleVADR backend_bryan...
start "eleVADR backend_bryan" cmd /k "cd /d ""%ROOT%"" && python -m backend_bryan.auth.env_runner backend_bryan.integration.http_reference_server"

timeout /t 2 /nobreak >nul

echo Starting eleVADR frontend...
start "eleVADR frontend" cmd /k "cd /d ""%ROOT%frontend"" && npm.cmd start -- --host 127.0.0.1"

echo.
echo eleVADR startup commands launched.
echo The backend window should report "Detector modules: 75", the selected Zeek runtime, and Authentication status.
echo.
exit
