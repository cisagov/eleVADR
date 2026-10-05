@echo off
setlocal

echo Stopping eleVADR frontend...
taskkill /FI "WINDOWTITLE eq eleVADR frontend" /T /F >nul 2>&1

echo Stopping eleVADR backend_bryan...
taskkill /FI "WINDOWTITLE eq eleVADR backend_bryan" /T /F >nul 2>&1

for /f "tokens=5" %%P in ('netstat -ano ^| findstr /R /C:":8765 .*LISTENING"') do (
  echo Stopping process %%P still listening on port 8765...
  taskkill /PID %%P /T /F >nul 2>&1
)

echo.
echo eleVADR frontend and backend_bryan have been stopped.
echo.
pause
