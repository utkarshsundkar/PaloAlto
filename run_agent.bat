@echo off
:: Opens a new visible CMD window showing the policy push live
start "Palo Alto - Policy Push Agent" cmd /k "cd /d %~dp0 && python main.py & echo. & echo ================================================ & echo  Done! Press any key to close this window... & echo ================================================ & pause > nul"
