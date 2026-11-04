@echo off
setlocal
set "ZEEK_IMAGE=zeek/zeek:9.0.0"
if defined ELEVADR_ZEEK_DOCKER_IMAGE set "ZEEK_IMAGE=%ELEVADR_ZEEK_DOCKER_IMAGE%"

echo Preparing eleVADR Zeek Docker runtime...
where docker >nul 2>&1
if errorlevel 1 (
  echo ERROR: Docker was not found. Install Docker Desktop or configure ELEVADR_ZEEK_COMMAND.
  exit /b 1
)

docker info >nul 2>&1
if errorlevel 1 (
  echo ERROR: Docker Desktop/Engine is installed but not running.
  exit /b 1
)

echo Pulling %ZEEK_IMAGE% ...
docker pull %ZEEK_IMAGE%
if errorlevel 1 exit /b 1

echo.
echo Zeek runtime is ready.
exit /b 0
