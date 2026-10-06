# How to run DPI

The demo and a live run use the same reading. The top of both reports is Network status. Demo packets are fake. Live packets come from the network this computer is using.

```bat
python DPI.py demo
python DPI.py live --count 80
```

Open `dpi-output\report.html` after the demo, and `live-output\report.html` after the live check. Both should show packets, name lookups, apps, devices, warnings, why it may be slow, and a talk-health line for each conversation. A repeat means the same packet number was seen twice. A reset means the talk was cut off. If the window says "Could not read one packet: it was cut off", a live packet was shorter than a full name lookup or handshake. DPI stopped rather than guess. It is not a decrypt error, and it does not mean Npcap is missing. Run the demo to confirm the program works. For live, close the window, open it with Run as administrator, and try again.

## Check this computer, then install

In the DPI folder:

```bat
python DPI.py check
python DPI.py setup
```

Check says if Python, Scapy, Npcap, and a network card are ready. Setup installs the Python pieces. It cannot install Npcap. Download that from https://npcap.com if the check says it is missing.

To make a double-click program on Windows, double-click `build_exe.bat`. The result is `dist\DPI.exe`. Live capture from that program still needs Npcap and Run as administrator.


You do not need to understand the Python files to use this.

1. Install Python from https://www.python.org and tick "Add python.exe to PATH".
2. Open the DPI folder.
3. In the folder address bar, type `cmd` and press Enter.
4. Type `python DPI.py demo` and press Enter.
5. Open `dpi-output\report.html`. That is a fake example, not your network.

To read your own network, right-click Command Prompt, choose Run as administrator, go to the folder, and type:

```bat
python DPI.py live --count 80
```

To keep watching instead of stopping after 80 packets, in that same Administrator window:

```bat
python DPI.py watch --seconds 15
```

It rewrites `live-output\report.html` every 15 seconds. Press Ctrl+C to stop. Refresh the page to see the latest warnings.

The report tells you, in normal words, which apps were named, which local devices answered, and whether a connection was reset or a packet looked repeated. It does not show the video, the search, or the page. Reports stay on this computer until you delete the output folder.


This program explains packets in normal words. It does not decrypt pages, videos, or searches.

Owner: Oluwatobiloba Benjamin Ogungbangbe. All rights reserved. You may use it for a noncommercial purpose. You may not sell it. See LICENSE.

## What you need

- Python 3.10 or newer. On Windows, tick "Add python.exe to PATH" when you install it.
- This project folder.
- For a live check on Windows: Npcap from https://npcap.com, and a terminal opened as Administrator.
- Only run a live check on a network you are allowed to monitor.

## First run, no network card needed

Open a terminal in this folder.

```bash
python -m pip install .
python DPI.py demo
```

Open `dpi-output/report.html`. The demo uses fake packets. It should name YouTube and Netflix, and show 2 local devices. That proves the program works before you touch a real network.

If `python` is not found on Windows, try `py` instead of `python`.

## Live check on the network this computer is using

This is the real run. The demo is only a test.

Windows: right-click Command Prompt, choose Run as administrator, then:

```bat
cd path\to\DPI
python DPI.py live --count 80
```

The report is `live-output\report.html`, not the demo folder. You can also double-click `run_live.bat` in an Administrator window.

Mac or Linux:

```bash
python3 DPI.py live --count 80
```

On Linux, put `sudo` in front if it says permission denied. While it listens, open YouTube, Netflix, or a normal page. It stops after 80 packets, or 30 seconds.

If it says no packets were read, the card name is wrong or the window is not Administrator. The error lists the cards it can see. Try `python DPI.py live --iface "Wi-Fi"`.

- Apps such as YouTube, Netflix, or Google, if the site name is still visible.
- How many local devices talked, or answered on that subnet.
- Conversations, sizes, and timing.

A missing app name does not mean the app was not used. A silent device is not listed.

## The window

```bat
python DPI.py window
```

Or double-click `run_window.bat` on Windows. Run demo needs no admin rights. Check this network needs the same Administrator window as the live check.

## If `dpi` is not recognised

The install can succeed and still not put `dpi` on PATH. Use `python DPI.py demo` or `python DPI.py live`. That does not need the `dpi` command.

## Words

| Word | Meaning |
| --- | --- |
| Packet | One small piece of network data. |
| Port | A door number. 443 usually means encrypted web. |
| Conversation | Both directions between the same two computers. |
| App name | A match on a visible site name, not the video or search. |
| Device count | Who talked during the check, or who answered on the local network. |
