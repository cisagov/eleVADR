@echo off
setlocal EnableExtensions
cd /d "%~dp0"
if "%~1"=="" (
  echo Usage: create_elevadr_user.bat USERNAME [--role admin^|analyst^|read_only] [--email ADDRESS]
  exit /b 1
)
if not exist .elevadr-platform.env (
  echo ERROR: Run setup_elevadr_database.bat first.
  exit /b 1
)
call check_elevadr_database.bat
if errorlevel 1 exit /b 1
python -m backend_bryan.auth.env_runner backend_bryan.auth.create_user %*
exit /b %errorlevel%
