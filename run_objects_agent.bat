@echo off
:: Opens a new visible CMD window running the Objects Configuration Pusher
start "Palo Alto - Objects Configuration Agent" cmd /k "cd /d %~dp0 && python push_objects.py & echo. & echo ================================================ & echo  Done! Press any key to close this window... & echo ================================================ & pause > nul"
