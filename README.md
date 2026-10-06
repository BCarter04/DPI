# DPI 2.8.0

Network traffic explained in plain English. It does not decrypt pages, videos, or searches.

- Live capture and a fake demo use the same report
- DNS health: answered, failed, and average time
- App names with the site that matched
- Device count and a phones, printers, and TVs label
- Talk health, reading score, download and upload bytes
- Watch mode that refreshes the report

## Try it

Network traffic explained in plain English. It does not decrypt pages, videos, or searches.

The demo and a live run use the same report. The top of the page is Network status. The traffic mix includes a best guess from the port and, when a site name is visible, a match from a list of common apps used in the UK and elsewhere.

## Try it

```bat
python DPI.py demo
python DPI.py live --count 80
```

Open `dpi-output\report.html` or `live-output\report.html`. The full steps are in [HOW_TO_USE.md](HOW_TO_USE.md). What each file does is in [NOTES.md](NOTES.md). What is stored is in [PRIVACY.md](PRIVACY.md).

| Command | What it does |
| --- | --- |
| `python DPI.py demo` | Fake packets. No admin rights. |
| `python DPI.py live --count 80` | The network this computer is using. |
| `python DPI.py watch --seconds 15` | Keeps reading and refreshes the report. |
| `python DPI.py check` | Says if this computer is ready. |
| `python DPI.py setup` | Installs the Python pieces. |
| `build_exe.bat` | Builds `dist\DPI.exe` on Windows. |

A live check on Windows needs Npcap and Run as administrator. Only monitor a network you are allowed to monitor. Owner: Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.

A small package that reads network packets and explains them in plain words.

It does not decrypt anything. Encrypted pages stay encrypted. It reports what a network can already see: who talked to whom, which port, packet size, timing, DNS lookup names, and the server name if a TLS handshake still shows it.

Only capture a network you are allowed to monitor. How to run it on another computer is in [HOW_TO_USE.md](HOW_TO_USE.md). Notes on what the code does now, and what it will do later, are in [NOTES.md](NOTES.md).

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
| `python DPI.py window` | Opens the window. No PATH change needed. |

`python DPI.py --demo` still works if you have not installed the package.

Live capture on Windows needs Npcap and an Administrator terminal. On Linux it may need `sudo dpi live`.

## What makes this version different

- It installs as a normal command, so another person can use it on their machine.
- It picks the connected interface instead of a hardcoded name.
- It groups both directions into conversations.
- It shows lookup names and TLS server names when they are visible.
- It keeps a short handshake fingerprint so two encrypted flows can be compared without opening them.
- The HTML report says what stands out, in one list, instead of only printing counts.

## Owner

Oluwatobiloba Benjamin Ogungbangbe is the owner. All rights reserved.

Use and changes are allowed for a noncommercial purpose under the PolyForm Noncommercial License 1.0.0. Selling is not allowed without written permission. Copies must keep the Required Notice and the license. Ideas do not transfer ownership. See [LICENSE](LICENSE), [NOTICE](NOTICE), and [CONTRIBUTING.md](CONTRIBUTING.md).
