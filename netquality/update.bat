@echo off
REM Update Network Vitals in place: pulls the latest netquality.py from the
REM netvitals repo and replaces this copy (previous version kept as .bak).
title Network Vitals updater
python "%~dp0netquality.py" --update %*
pause
