@echo off
title Palo Alto Networks - High Availability (HA) Agent
color 0B
echo ================================================================
echo    PALO ALTO HIGH AVAILABILITY CONFIGURATION AGENT
echo ================================================================
echo.

python push_ha_config.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] HA configuration push failed. Check output above.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo ================================================================
echo   HA Configuration and Commit completed successfully!
echo ================================================================
pause
