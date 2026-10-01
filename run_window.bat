@echo off
cd /d "%~dp0"
python DPI.py window
if errorlevel 1 pause
