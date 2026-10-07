@echo off
setlocal
cd /d "%~dp0"
if not exist .elevadr-platform.env (
  echo ERROR: Run setup_elevadr_database.bat first.
  exit /b 1
)
docker compose --env-file .elevadr-platform.env -f docker-compose.mongodb.yml up -d --wait --wait-timeout 90
if errorlevel 1 exit /b 1
call check_elevadr_database.bat
