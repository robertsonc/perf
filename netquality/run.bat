@echo off
REM Launch netquality. Prompts for the peer IP if not supplied.
setlocal
set PEER=%1
if "%PEER%"=="" set /p PEER=Enter the other workstation IP (peer): 
python "%~dp0netquality.py" --peer %PEER% %2 %3 %4 %5 %6
if errorlevel 1 pause
