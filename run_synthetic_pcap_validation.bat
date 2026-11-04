@echo off
setlocal
cd /d "%~dp0"
python -m backend.regression.synthetic_pcap_corpus --live
if errorlevel 1 exit /b %errorlevel%
endlocal
