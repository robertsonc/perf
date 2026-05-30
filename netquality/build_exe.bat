@echo off
REM Build a standalone Windows .exe (requires: pip install pyinstaller)
setlocal
pyinstaller --onefile --name netquality "%~dp0netquality.py"
echo.
echo Built dist\netquality.exe
pause
