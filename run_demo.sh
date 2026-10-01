#!/bin/sh
cd "$(dirname "$0")" || exit 1
echo "Installing the one dependency..."
python3 -m pip install -r requirements.txt || {
  echo "Python 3 was not found. Install Python 3.10 or newer."
  exit 1
}
echo
echo "Running the demo. These are fake packets, not your network."
python3 DPI.py --demo || exit 1
echo
echo "Open this file in a browser: dpi-output/report.html"
