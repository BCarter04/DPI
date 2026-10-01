# How to use DPI

This is a small program that looks at network packets and explains them in normal words.

It does not decrypt anything. It does not open encrypted pages. It only reports what a network can already see: who talked to whom, which port, how big the packets were, how long it lasted, and the site name if the start of an encrypted connection still shows it.

## Words you will see

| Word | Meaning |
| --- | --- |
| Packet | One small piece of network data. |
| Port | A door number. Port 443 is the usual door for encrypted web. |
| Conversation | Both directions between the same two computers. |
| Server name | A site name sometimes sent before encryption starts. It is not the page. |
| Other | A port this program does not recognise. That is not an error. |

A port is only a hint. The server name, when it is visible, is a better hint.

## Put it on a computer

You need Python 3.10 or newer. Check with:

```bash
python --version
```

If that fails, try `python3 --version`. Install Python from https://www.python.org/downloads/ if it is missing. On Windows, tick "Add python.exe to PATH" during install.

Then:

1. Copy this folder onto the computer. A USB stick, a zip, or `git clone` all work.
2. Open a terminal in that folder.
3. Install the one dependency and run the demo.

Windows:

```bat
python -m pip install -r requirements.txt
python DPI.py --demo
start dpi-output\report.html
```

Mac or Linux:

```bash
python3 -m pip install -r requirements.txt
python3 DPI.py --demo
```

Then open `dpi-output/report.html` in a browser.

The demo uses fake packets. It does not need a network card, admin rights, or Npcap. That is the right first run for anyone trying the app.

There is also a helper script:

- Windows: double-click `run_demo.bat`, or run it from the folder.
- Mac or Linux: `bash run_demo.sh`

## Give it to someone else

Zip the folder and send the zip. They unzip it, install Python if needed, and run the demo commands above.

Do not send the `dpi-output` folder. That is only the report from a run. The program makes a new one.

This is a program on their computer, not a website. It should stay that way for a live capture, because the packets are on that machine.

## Look at a real capture

Only do this on a network you are allowed to monitor.

From a saved capture file:

```bash
python DPI.py --pcap mycapture.pcap
```

Live, on Windows, the interface is often called `Wi-Fi`:

```bash
python DPI.py --iface "Wi-Fi" --count 100
```

Live, on Linux, it is often `eth0` or `wlan0`:

```bash
python DPI.py --iface eth0 --count 100
```

Live capture needs permission to sniff. On Windows, install Npcap from https://npcap.com/ and run the terminal as Administrator. On Linux, run with `sudo` or grant the capture capability. The demo does not need any of that.

## What you get

Each run writes a folder, `dpi-output` by default:

- `report.html` — the page to open
- `summary.json` — the same facts, for another program
- `conversations.csv` — one row per conversation, opens in Excel

Use `--out some-folder` to write somewhere else.

## What it will not do

It will not decrypt HTTPS. It will not bypass a filter. If the server name is hidden, the report says so instead of guessing.
