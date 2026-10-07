@echo off
setlocal
cd /d "%~dp0"
if "%~1"=="" (
  echo Usage: validate_elevadr_backup.bat ^<backup.zip^>
  exit /b 2
)
python -m backend_bryan.auth.env_runner backend_bryan.auth.backup_restore validate "%~1"
exit /b %errorlevel%
