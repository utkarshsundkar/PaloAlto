@echo off
:: Opens a new visible CMD window running the NAT Policy Pusher
start "Palo Alto - NAT Policy Agent" cmd /k "cd /d %~dp0 && python push_nat_policies.py & echo. & echo ================================================ & echo  Done! Press any key to close this window... & echo ================================================ & pause > nul"
