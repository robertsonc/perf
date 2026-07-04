@echo off
REM Launch Network Vitals. Shows this machine's IP, remembers the last peer
REM used (lastpeer.txt next to this script), and prompts with it as the
REM default. Pass the peer as the first argument to skip the prompt.
setlocal EnableDelayedExpansion
title Network Vitals
set "HISTFILE=%~dp0lastpeer.txt"

REM --- this machine's IPv4 (adapter "Ethernet 3" on AutoPod workstations) ---
set "MYIP="
for /f "usebackq delims=" %%a in (`powershell -NoProfile -Command "(Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias 'Ethernet 3' -ErrorAction SilentlyContinue).IPAddress" 2^>nul`) do set "MYIP=%%a"

echo ==============================================
echo    Network Vitals
if defined MYIP (
    echo    This machine ^(Ethernet 3^): !MYIP!
) else (
    echo    Adapter "Ethernet 3" not found. IPv4 addresses:
    powershell -NoProfile -Command "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*'} | ForEach-Object { '      {0}  ({1})' -f $_.IPAddress, $_.InterfaceAlias }"
)
echo ==============================================
echo.

REM --- peer IP: argument beats prompt; prompt defaults to the last one used ---
set "PEER=%~1"
set "LAST="
if exist "%HISTFILE%" set /p LAST=<"%HISTFILE%"
if not defined PEER (
    if defined LAST (
        set /p PEER=Enter peer IP [Enter = !LAST!]:
        if not defined PEER set "PEER=!LAST!"
    ) else (
        set /p PEER=Enter peer IP:
    )
)
if not defined PEER (
    echo No peer IP given - nothing to do.
    pause
    exit /b 1
)

>"%HISTFILE%" echo !PEER!
echo Starting against peer !PEER! ...
python "%~dp0netquality.py" --peer !PEER! %2 %3 %4 %5 %6 %7 %8 %9
if errorlevel 1 pause
