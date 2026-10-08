@echo off
setlocal EnableExtensions
set "ROOT=%~dp0"
set "ZEEK_IMAGE=zeek/zeek:9.0.0"
if defined ELEVADR_ZEEK_DOCKER_IMAGE set "ZEEK_IMAGE=%ELEVADR_ZEEK_DOCKER_IMAGE%"

echo ==================================================
echo          eleVADR Development Restart
echo ==================================================
echo WARNING: In-memory processing jobs will be lost.
echo MongoDB, stored reports, PCAPs, and contexts are preserved.
echo.

echo [1/6] Stopping existing frontend and backend...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ports=@(5173,8765); foreach($port in $ports) { $conns=@(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue); foreach($c in $conns) { $procId=$c.OwningProcess; $p=Get-CimInstance Win32_Process -Filter ('ProcessId = '+$procId) -ErrorAction SilentlyContinue; if(-not $p){continue}; $cmd=[string]$p.CommandLine; $frontend=($port -eq 5173 -and $p.Name -match 'node' -and $cmd -match 'vite'); $backend=($port -eq 8765 -and $cmd -match 'backend_bryan'); if($frontend -or $backend){Write-Host ('Stopping '+$p.Name+' PID '+$procId+' on port '+$port); taskkill /PID $procId /T /F | Out-Null} else {Write-Host ('ERROR: Port '+$port+' is occupied by '+$p.Name+' PID '+$procId); exit 1}}}"
if errorlevel 1 goto :fail

echo [2/6] Cleaning up labeled eleVADR Zeek containers...
where docker >nul 2>&1
if errorlevel 1 goto :no_docker
docker info >nul 2>&1
if errorlevel 1 goto :no_docker
for /f "delims=" %%C in ('docker ps -aq --filter "label=elevadr.managed=true" --filter "label=elevadr.component=zeek"') do (
  echo Removing eleVADR Zeek container %%C
  docker rm -f %%C
  if errorlevel 1 goto :fail
)
goto :docker_done
:no_docker
echo Docker is unavailable; skipping Zeek cleanup.
:docker_done

echo [3/6] Waiting for ports to be released...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ports=@(5173,8765); for($i=0;$i -lt 30;$i++){ $busy=@($ports | Where-Object {Get-NetTCPConnection -LocalPort $_ -State Listen -ErrorAction SilentlyContinue}); if($busy.Count -eq 0){exit 0}; Start-Sleep -Milliseconds 500 }; Write-Host 'ERROR: Port 5173 or 8765 remains occupied'; exit 1"
if errorlevel 1 goto :fail

echo [4/6] Checking configuration...
if exist "%ROOT%.elevadr-platform.env" (
  echo Platform environment file found.
) else (
  echo WARNING: Platform environment file missing; authentication may be disabled.
)
if defined ELEVADR_ZEEK_COMMAND (
  echo Zeek: explicit command configured.
) else (
  where zeek >nul 2>&1
  if not errorlevel 1 (
    echo Zeek: native runtime available.
  ) else (
    echo Zeek: Docker fallback %ZEEK_IMAGE%
  )
)

echo [5/6] Starting backend_bryan...
start "eleVADR backend_bryan" cmd /k "cd /d ""%ROOT%"" && python -m backend_bryan.auth.env_runner backend_bryan.integration.http_reference_server --host 127.0.0.1 --port 8765"

echo [6/6] Starting frontend...
start "eleVADR frontend" cmd /k "cd /d ""%ROOT%frontend"" && npm.cmd start -- --host 127.0.0.1 --port 5173 --strictPort"

echo.
echo Services launched. Check their terminal windows for startup errors.
echo Frontend: http://127.0.0.1:5173/
echo Backend:  http://127.0.0.1:8765/
exit /b 0

:fail
echo Startup aborted. Review the error above.
exit /b 1
