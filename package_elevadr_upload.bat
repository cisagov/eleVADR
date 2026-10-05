@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%package_elevadr_upload.ps1" %*
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%
