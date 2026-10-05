"""Check this computer, then install what the program needs.

Copyright (c) 2023-2026 Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.

What it does now
    Looks at Python, the Scapy library, and whether a network card can be
    listed. On Windows it also says if Npcap is missing. Setup installs the
    Python pieces. It cannot install Npcap for you. That is a separate
    download, and the live check still needs an Administrator window.

What it will do
    The .exe build uses the same check. A later build can open the Npcap
    page for you. It will not hide the Administrator step.
"""

import importlib.util
import os
import shutil
import sys


def check_computer():
    """Return plain lines saying what is ready and what is missing."""
    lines = []
    ok = True
    lines.append(f"Python {sys.version.split()[0]} is installed.")
    if importlib.util.find_spec("scapy") is None:
        ok = False
        lines.append("Missing: Scapy. Run python DPI.py setup")
    else:
        lines.append("Scapy is installed. That is the packet reader.")
    if os.name == "nt":
        npcap = os.path.exists(r"C:\Windows\System32\Npcap") or os.path.exists(r"C:\Windows\System32\wpcap.dll")
        if npcap:
            lines.append("Npcap looks installed. A live check still needs Run as administrator.")
        else:
            ok = False
            lines.append("Npcap was not found. Install it from https://npcap.com, then run as Administrator.")
    else:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            lines.append("This window is not root. A live check on Linux or Mac may need sudo.")
        else:
            lines.append("This window can read packets if the card is available.")
    try:
        from dpi.capture import list_interfaces
        names = list_interfaces()
        lines.append("Network cards seen: " + ", ".join(names[:6]))
    except Exception as error:
        ok = False
        lines.append(f"Could not list network cards: {error}")
    lines.append("Ready." if ok else "Not ready yet. Fix the missing line above, then run the check again.")
    return lines


def install_python_pieces():
    """Install this project and Scapy for the current Python."""
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "."])
    return "Installed the Python pieces for this folder."


def exe_ready():
    """Say whether PyInstaller is present. The .exe is built on Windows."""
    if shutil.which("pyinstaller") or importlib.util.find_spec("PyInstaller"):
        return "PyInstaller is installed. On Windows, double-click build_exe.bat."
    return "PyInstaller is not installed. build_exe.bat installs it, then makes DPI.exe."
