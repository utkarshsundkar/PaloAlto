@echo off
:: Opens a new visible CMD window running the Security Policy Agent
start "Palo Alto - Security Policy Agent" cmd /k "cd /d %~dp0 && python security_policy_agent.py & echo. & echo ================================================ & echo  Done! Press any key to close this window... & echo ================================================ & pause > nul"
