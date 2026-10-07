@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo eleVADR first-run setup
echo ============================================================

python -m backend_bryan.integration.deployment_preflight
if errorlevel 1 exit /b 1

echo.
echo [1/4] Installing platform Python dependencies...
python -m pip install -r backend_bryan\requirements-platform.txt
if errorlevel 1 exit /b 1

echo.
echo [2/4] Installing frontend dependencies from lock file...
pushd frontend
call npm.cmd ci
set "RC=%ERRORLEVEL%"
popd
if not "%RC%"=="0" exit /b %RC%

echo.
echo [3/4] Preparing local MongoDB...
call setup_elevadr_database.bat
if errorlevel 1 exit /b 1

echo.
echo [4/4] Checking administrator bootstrap...
python -m backend_bryan.auth.env_runner backend_bryan.auth.has_users
set "USER_CHECK_RC=%ERRORLEVEL%"
if "%USER_CHECK_RC%"=="0" goto users_ready
if not "%USER_CHECK_RC%"=="1" exit /b %USER_CHECK_RC%

echo No eleVADR users exist yet. Create the first administrator.
set /p "ELEVADR_FIRST_ADMIN=Administrator username [admin]: "
if "%ELEVADR_FIRST_ADMIN%"=="" set "ELEVADR_FIRST_ADMIN=admin"
call create_elevadr_user.bat "%ELEVADR_FIRST_ADMIN%" --role admin
if errorlevel 1 exit /b 1

:users_ready
python -m backend_bryan.auth.enable_auth
if errorlevel 1 exit /b 1

python -m backend_bryan.integration.deployment_preflight --initialized
if errorlevel 1 exit /b 1

echo.
echo PASS: eleVADR first-run setup completed.
echo Start the application with start_elevadr.bat
exit /b 0
