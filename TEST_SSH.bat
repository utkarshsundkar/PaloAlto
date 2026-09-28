@echo off
:: Opens a new visible CMD window showing the SSH test live
start "Palo Alto - SSH Test" cmd /k "cd /d %~dp0 && python test_ssh.py & echo. & echo Press any key to close... & pause > nul"