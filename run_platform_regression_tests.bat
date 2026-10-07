@echo off
setlocal
cd /d "%~dp0"
echo ============================================================
echo eleVADR platform regression/security gate
echo ============================================================
python -m pytest -q backend_bryan\tests\test_auth_foundation.py backend_bryan\tests\test_auth_http_boundary.py backend_bryan\tests\test_account_management.py backend_bryan\tests\test_report_persistence.py backend_bryan\tests\test_capture_retention.py backend_bryan\tests\test_platform_hardening.py backend_bryan\tests\test_role_permissions.py backend_bryan\tests\test_audit_history.py backend_bryan\tests\test_storage_management.py backend_bryan\tests\test_backup_restore.py backend_bryan\tests\test_platform_ux_contract.py
if errorlevel 1 exit /b 1
echo.
echo PASS: eleVADR platform regression/security gate completed successfully.
endlocal
