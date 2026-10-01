# DPI 2.0

This is the follow-on to [BCarter04/DPI](https://github.com/BCarter04/DPI). The old repository could not be updated from this chat, so this folder is the new main project.


A small tool that reads network packets and explains them in plain language.

It does **not** decrypt anything. Encrypted page contents stay encrypted. It only uses what is already visible on the wire: who talked to whom, which port, how big the packets were, how long the capture lasted, and the server name if a TLS handshake still shows it.

Only capture a network you are allowed to monitor.

New here? Read [HOW_TO_USE.md](HOW_TO_USE.md). It is the short guide for installing this on a computer and handing it to someone else.

## Try the demo

No network card and no install beyond Python and Scapy.

```bash
pip install -r requirements.txt
python DPI.py --demo
```

Windows can also double-click `run_demo.bat`. Mac or Linux can run `bash run_demo.sh`.

That writes three files into `dpi-output/`:

- `report.html` — a one-page reading of the traffic
- `summary.json` — the same facts, for another program
- `conversations.csv` — one row per conversation

Open `report.html` in a browser.

## Other ways to run it

```bash
python DPI.py --pcap mycapture.pcap
python DPI.py --iface "Wi-Fi" --count 100
python DPI.py --demo --out my-report
```

Live capture needs permission to sniff, and on Windows it needs Npcap. The demo does not.

## What the words mean

| Word | Plain meaning |
| --- | --- |
| Packet | One small chunk of network data. |
| Port | A door number on a computer. Port 443 is the usual door for encrypted web. |
| Conversation | Both directions between the same two computers and ports. |
| Server name (SNI) | The site name sometimes sent before encryption starts. It is not the page. |
| Other | A port this tool does not have in its short well-known list. |

A port is only a hint. Many apps use port 443. The server name, when it is visible, is a better hint than the port alone.

## What changed from the first sketch

The first version labeled single packets by port and treated the whole capture as one second long. This version:

- groups packets into conversations
- measures the real time from the first packet to the last
- reads a TLS server name when the handshake is visible
- writes an HTML page, JSON, and CSV
- runs a built-in demo so you can see it without a live interface

## Files

- `DPI.py` — the program
- `report.py` — the HTML page
- `HOW_TO_USE.md` — install and hand-off guide
- `run_demo.bat` / `run_demo.sh` — one-step demo
- `requirements.txt` — the only dependency, Scapy

A windowed app and a double-click `.exe` can come later. The command above is the working core.
