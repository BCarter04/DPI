@echo off
cd /d "%~dp0"
echo This builds DPI.exe on this Windows computer. It does not replace Npcap.
python DPI.py setup
python -m pip install pyinstaller
python -m PyInstaller --onefile --name DPI --console DPI.py
echo.
echo If the build worked, DPI.exe is in the dist folder.
echo Live capture still needs Npcap and Run as administrator.
pause
