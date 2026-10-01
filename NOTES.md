# What this code does, and what it will do

Read this before the Python files. Each file also has a short note at the top.

## What it does now

DPI reads packets and writes a plain-language report. It does not decrypt anything.

1. `dpi/cli.py` is the front door. `dpi demo`, `dpi live`, and `dpi pcap file.pcap` all come through here.
2. `dpi/capture.py` gets the packets. The demo builds fake ones. Live mode picks the connected network card. A pcap file is a saved capture.
3. `dpi/analyze.py` turns packets into facts: port guess, conversation, DNS name, TLS server name, handshake fingerprint, busiest addresses.
4. `dpi/report.py` writes `report.html`. The same facts also go to `summary.json` and `conversations.csv`.
5. `DPI.py` is the old way to start the program. After `python -m pip install .`, the `dpi` command is the normal way.

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
| `dpi/report.py` | One HTML page | Can add charts without adding a new dependency |
| `run_live.bat` | Installs the package and runs the live check on Windows | Can become the thing the `.exe` launches |
