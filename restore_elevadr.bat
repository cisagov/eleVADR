@echo off
setlocal
cd /d "%~dp0"
if "%~1"=="" (
  echo Usage: restore_elevadr.bat ^<backup.zip^> --yes
  echo Restore replaces the current eleVADR MongoDB database and storage directory.
  exit /b 2
)
if /I not "%~2"=="--yes" (
  echo ERROR: Restore is destructive. Re-run with --yes after validating the backup.
  exit /b 2
)
call check_elevadr_database.bat
if errorlevel 1 exit /b 1
python -m backend_bryan.auth.env_runner backend_bryan.auth.backup_restore restore "%~1" --yes
exit /b %errorlevel%
