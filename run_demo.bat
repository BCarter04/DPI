@echo off
cd /d "%~dp0"
echo Installing the one dependency...
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo Python was not found. Install Python 3.10 or newer and tick "Add python.exe to PATH".
  pause
  exit /b 1
)
echo.
echo Running the demo. These are fake packets, not your network.
python DPI.py --demo
if errorlevel 1 (
  pause
  exit /b 1
)
echo.
echo Opening the report...
start "" "dpi-output\report.html"
pause
