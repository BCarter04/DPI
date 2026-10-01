#!/bin/sh
cd "$(dirname "$0")" || exit 1
python3 -m pip install .
dpi live --count 80 --out live-output || {
  echo "Live capture failed. Try: sudo dpi live --count 80"
  exit 1
}
echo "Open live-output/report.html"
