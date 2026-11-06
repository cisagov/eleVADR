@echo off
setlocal
cd /d "%~dp0"
if not exist .elevadr-platform.env exit /b 0
docker compose --env-file .elevadr-platform.env -f docker-compose.mongodb.yml stop mongodb
