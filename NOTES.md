# What this code does, and what it will do

Read this before the Python files. Each file also has a short note at the top.

## What it does now

The demo and the live check call the same `analyze()` and the same `write_html()`. If a reading is added, it must show in both. The demo uses fake packets. Live uses the network this computer is connected to.

1. `dpi/cli.py` starts demo, live, watch, check, and setup.
2. `dpi/capture.py` builds the fake packets or reads the live card.
Traffic mix is built in `dpi/analyze.py`. The port list makes the first guess. If a handshake or lookup shows a known site, that app name is added to the same mix. `dpi/report.py` draws the bars and explains them in plain words. Demo and live use both files.
4. `dpi/report.py` writes the Network status block at the top of report.html.
5. `dpi/why.py` turns those facts into one slow-link sentence.
6. `HOW_TO_USE.md` is the run guide for someone who does not write code.

A port guess is only a hint. Port 443 usually means encrypted web, but other apps use it too. A server name is read only if the handshake still shows it. The page itself stays hidden.

## What it will do later

These are not built yet. They are the next useful steps, still without decryption.

- A small window, then a double-click `.exe`, so a user does not need a terminal.
- A longer live view that keeps updating while the laptop stays on the network.
- A saved history of reports, so two runs can be compared.
- Clearer app guesses from packet size and timing, not only from the port.
- A warning when one computer talks to many unusual ports. That can be a scan, or just a noisy app, so it stays a hint.

## File map

| File | Does now | Will do later |
| --- | --- | --- |
| `dpi/cli.py` | Chooses demo, live, or pcap, then prints and saves the report | Can grow a window that calls the same functions |
| `dpi/capture.py` | Demo packets, live sniff, pcap read, pick the connected interface | Can keep listening instead of stopping after a set count |
| `dpi/analyze.py` | Port guess, conversations, names, fingerprint, highlights | Can compare size and timing patterns across runs |
| `dpi/devices.py` | Counts local devices seen in the capture, and on a live run asks the local subnet who is awake | Can later add a device name. It will not scan the public internet |
| `run_live.bat` | Installs the package and runs the live check on Windows | Can become the thing the `.exe` launches |
