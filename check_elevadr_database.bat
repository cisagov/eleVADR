@echo off
setlocal
cd /d "%~dp0"
if not exist .elevadr-platform.env (
  echo ERROR: .elevadr-platform.env does not exist. Run setup_elevadr_database.bat first.
  exit /b 1
)

docker compose --env-file .elevadr-platform.env -f docker-compose.mongodb.yml ps --status running mongodb >nul 2>&1
if errorlevel 1 (
  echo ERROR: eleVADR MongoDB container is not running.
  exit /b 1
)

for /f "delims=" %%H in ('docker inspect --format "{{.State.Health.Status}}" elevadr-mongodb 2^>nul') do set "HEALTH=%%H"
if /I not "%HEALTH%"=="healthy" (
  echo ERROR: eleVADR MongoDB health is %HEALTH%.
  exit /b 1
)

echo PASS: eleVADR MongoDB is running and healthy on localhost only.
exit /b 0
