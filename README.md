# DPI 2.0

A small package that reads network packets and explains them in plain words.

It does not decrypt anything. Encrypted pages stay encrypted. It reports what a network can already see: who talked to whom, which port, packet size, timing, DNS lookup names, and the server name if a TLS handshake still shows it.

Only capture a network you are allowed to monitor. The short guide is [HOW_TO_USE.md](HOW_TO_USE.md). Notes on what the code does now, and what it will do later, are in [NOTES.md](NOTES.md).

## Install it on a live machine

Python 3.10 or newer is required.

```bash
git clone https://github.com/BCarter04/DPI.git
cd DPI
python -m pip install .
dpi demo
```

After that, the `dpi` command works from any folder.

| Command | What it does |
| --- | --- |
| `dpi demo` | Fake packets. No network card and no admin rights. |
| `dpi live` | Reads the network this computer is connected to. |
| `dpi live --iface "Wi-Fi" --count 80` | Same, but you name the interface. |
| `dpi pcap capture.pcap` | Reads a saved capture file. |

`python DPI.py --demo` still works if you have not installed the package.

Live capture on Windows needs Npcap and an Administrator terminal. On Linux it may need `sudo dpi live`.

## What makes this version different

- It installs as a normal command, so another person can use it on their machine.
- It picks the connected interface instead of a hardcoded name.
- It groups both directions into conversations.
- It shows lookup names and TLS server names when they are visible.
- It keeps a short handshake fingerprint so two encrypted flows can be compared without opening them.
- The HTML report says what stands out, in one list, instead of only printing counts.

The old MIT license is unchanged.
