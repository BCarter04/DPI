@echo off
cd /d "%~dp0"
echo Installing DPI so the dpi command works on this machine...
python -m pip install .
if errorlevel 1 (
  echo Python was not found. Install Python 3.10 or newer and tick Add python.exe to PATH.
  pause
  exit /b 1
)
echo Running the live check. Run this window as Administrator after Npcap is installed.
python DPI.py live --count 80 --out live-output
if errorlevel 1 (
  echo Live capture failed. Install Npcap from https://npcap.com and run as Administrator.
  pause
  exit /b 1
)
start "" "live-output\report.html"
pause
