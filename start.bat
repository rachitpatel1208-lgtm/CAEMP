@echo off
title CAEMP // OMNITRIX EDITION - Unified Platform
cd /d "%~dp0"
echo ======================================================================
echo    CAEMP // OMNITRIX EDITION - UNIFIED CYBERSECURITY PLATFORM
echo    Featuring: CAEMP Network Exposure + PhishGuard URL Scanner
echo ======================================================================
python run.py
if errorlevel 1 (
    echo.
    echo [!] Server exited or python error. Trying fallback: python app.py
    python app.py
)
pause
