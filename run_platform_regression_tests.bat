@echo off
setlocal
cd /d "%~dp0"
echo ============================================================
echo eleVADR platform regression/security gate
echo ============================================================
python -m pytest -q backend\tests\test_auth_foundation.py backend\tests\test_auth_http_boundary.py backend\tests\test_account_management.py backend\tests\test_report_persistence.py backend\tests\test_capture_retention.py backend\tests\test_platform_hardening.py backend\tests\test_role_permissions.py backend\tests\test_audit_history.py backend\tests\test_storage_management.py backend\tests\test_backup_restore.py backend\tests\test_platform_ux_contract.py
if errorlevel 1 exit /b 1
echo.
echo PASS: eleVADR platform regression/security gate completed successfully.
endlocal
