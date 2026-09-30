@echo off
title Palo Alto & Cisco FTD Migration Agent Dashboard
echo ========================================================
echo  Palo Alto & Cisco FTD Policy Migration Agent UI
echo ========================================================
echo  Starting backend web server on http://localhost:8080...
echo.

start "" http://localhost:8080
python server.py

pause
