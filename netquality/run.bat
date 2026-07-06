@echo off
REM Launch Network Vitals. Prompts for the peer IP if not supplied.
REM Usage:  run.bat [peer-ip] [extra netquality.py args...]
REM Extra args override/extend the defaults set below.
setlocal EnableDelayedExpansion

REM ---- site defaults (edit these once for your environment) --------------
REM 8164 B payload + 28 B UDP/IP = an 8192-byte frame (this system's max).
set SIZE=8164
REM DF=--dont-fragment makes oversized probes drop instead of fragmenting,
REM so jumbo problems show up as loss. Set "set DF=" to disable.
set DF=--dont-fragment
REM -------------------------------------------------------------------------

set PEER=%1
if "%PEER%"=="" set /p PEER=Enter the other workstation IP (peer): 

REM collect any args after the peer IP so they pass straight through
set EXTRA=
:collect
shift
if "%~1"=="" goto run
set EXTRA=!EXTRA! %1
goto collect

:run
python "%~dp0netquality.py" --peer %PEER% --size %SIZE% %DF% !EXTRA!
if errorlevel 1 pause
