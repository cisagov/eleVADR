@echo off
setlocal
cd /d "%~dp0"
if not exist .elevadr-platform.env (
  echo ERROR: Run setup_elevadr_database.bat first.
  exit /b 1
)
call check_elevadr_database.bat
if errorlevel 1 exit /b 1
python -m backend_bryan.auth.env_runner backend_bryan.auth.backup_restore backup %*
exit /b %errorlevel%
