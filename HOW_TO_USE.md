# How to use DPI on a live machine

This program explains packets in normal words. It does not decrypt pages.

## Install

1. Install Python 3.10 or newer. On Windows, tick "Add python.exe to PATH".
2. Copy this folder onto the computer, or run `git clone https://github.com/BCarter04/DPI.git`.
3. Open a terminal in the folder and run:

```bash
python -m pip install .
dpi demo
```

Open `dpi-output/report.html`. The demo is fake traffic, so it is the right first run.

## Live network

Only do this on a network you are allowed to monitor.

```bash
dpi live --count 80
```

Windows also has `run_live.bat`. Run it as Administrator after installing Npcap from https://npcap.com.

If the interface name is wrong, run `dpi live --iface "Wi-Fi"` or `dpi live --iface Ethernet`.

## Saved capture

```bash
dpi pcap mycapture.pcap
```

## Words

| Word | Meaning |
| --- | --- |
| Packet | One small piece of network data. |
| Port | A door number. 443 is the usual encrypted-web door. |
| Conversation | Both directions between the same two computers. |
| Server name | A site name sometimes sent before encryption starts. Not the page. |
| Fingerprint | A short label of the handshake shape. Not the contents. |
