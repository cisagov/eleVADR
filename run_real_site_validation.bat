@echo off
setlocal
cd /d "%~dp0"

if "%~1"=="" goto :usage
if "%~2"=="" goto :usage

if "%~3"=="" (
  python -m backend_bryan.regression.dataset18_real_site_runner --pcap "%~1" --context "%~2"
) else (
  python -m backend_bryan.regression.dataset18_real_site_runner --pcap "%~1" --context "%~2" --output-dir "%~3"
)
exit /b %errorlevel%

:usage
echo Usage: run_real_site_validation.bat ^<pcap^> ^<detection-context.json^> [output-directory]
echo Example:
echo   run_real_site_validation.bat "C:\captures\site.pcap" "C:\captures\site-context.json" "C:\captures\site-review"
exit /b 2
