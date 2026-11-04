@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo eleVADR local MongoDB setup
echo ============================================================

where docker >nul 2>&1
if errorlevel 1 (
  echo ERROR: Docker is not installed or is not on PATH.
  exit /b 1
)
docker info >nul 2>&1
if errorlevel 1 (
  echo ERROR: Docker Desktop/Engine is not running.
  exit /b 1
)

python -m backend.auth.local_runtime init
if errorlevel 1 exit /b 1

echo Starting MongoDB Community Server...
docker compose --env-file .elevadr-platform.env -f docker-compose.yml up -d --wait --wait-timeout 90 mongodb
if errorlevel 1 (
  echo ERROR: MongoDB did not become healthy.
  docker compose --env-file .elevadr-platform.env -f docker-compose.yml ps mongodb
  exit /b 1
)

call check_elevadr_database.bat
if errorlevel 1 exit /b 1

echo.
echo MongoDB is ready. Authentication is still disabled by default.
echo Next: install platform Python dependencies, then run create_elevadr_user.bat.
exit /b 0
