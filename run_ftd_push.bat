@echo off
title Palo Alto - Cisco FTD Configuration Push Agent
color 0B
cls

echo =====================================================================
echo    PALO ALTO NETWORKS -- CISCO FTD MIGRATION PUSH AGENT
echo =====================================================================
echo.
echo Target Firewall : 10.233.188.122:22
echo Username        : admin
echo Source Config   : Cisco FTD running config
echo Total Commands  : 14,389 across 9 Stages
echo.
echo =====================================================================
echo  Select an option:
echo.
echo  [1] Dry-Run Mode (Safe Simulation - No changes made to firewall)
echo  [2] Live Push ALL Stages (Without Commit)
echo  [3] Live Push ALL Stages + AUTO COMMIT
echo  [4] Push Specific Stage Only (Interactive)
echo  [5] Re-parse FTD Config and Regenerate Command Files
echo  [6] Test SSH Connectivity
echo  [7] Exit
echo.
echo =====================================================================
set /p choice="Enter choice [1-7]: "

if "%choice%"=="1" (
    cls
    echo Running Dry-Run Simulation...
    python push_ftd_to_paloalto.py --dry-run
    pause
    goto :eof
)

if "%choice%"=="2" (
    cls
    echo Pushing Live Configuration to Palo Alto (10.233.188.122)...
    python push_ftd_to_paloalto.py --live
    pause
    goto :eof
)

if "%choice%"=="3" (
    cls
    echo Pushing Live Configuration with Auto-Commit to Palo Alto (10.233.188.122)...
    python push_ftd_to_paloalto.py --live --commit
    pause
    goto :eof
)

if "%choice%"=="4" (
    cls
    echo Available Stages:
    echo   01 - Security Zones
    echo   02 - Network Interfaces
    echo   03 - Service Objects
    echo   04 - Service Groups
    echo   05 - Address Objects
    echo   06 - Address Groups
    echo   07 - Static Routes
    echo   08 - NAT Policies
    echo   09 - Security Policies
    echo.
    set /p stg="Enter stage number (e.g. 01, 05, 09): "
    python push_ftd_to_paloalto.py --live --stage %stg%
    pause
    goto :eof
)

if "%choice%"=="5" (
    cls
    echo Re-parsing Cisco FTD running config and updating policies.xlsx...
    python parse_ftd_config.py
    python populate_excel_from_ftd.py
    python generate_panos_cli.py
    echo Done!
    pause
    goto :eof
)

if "%choice%"=="6" (
    cls
    echo Testing SSH connectivity to 10.233.188.122...
    python test_ssh.py
    pause
    goto :eof
)

if "%choice%"=="7" (
    exit /b 0
)

echo Invalid choice.
pause
