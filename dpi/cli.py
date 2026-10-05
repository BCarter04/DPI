"""Front door for the program.

Copyright (c) 2023-2026 Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.

What it does now
    Reads the command, gets packets, prints a short reading, and writes
    report.html, summary.json, and conversations.csv.

What it will do
    The same functions can sit behind a window later. The window should
    call main(), not copy this logic.
"""

import argparse
import csv
import json
import os
import sys

from dpi.analyze import analyze
from dpi.capture import build_demo_packets, capture_for_seconds, capture_live, choose_live_interface, load_pcap
from dpi.devices import devices_on_link
from dpi.report import write_html


def write_outputs(summary, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "summary.json")
    csv_path = os.path.join(out_dir, "conversations.csv")
    html_path = os.path.join(out_dir, "report.html")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
    with open(csv_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["who", "category", "name", "app", "packets", "bytes", "why"])
        for flow in summary["flows"]:
            writer.writerow([
                flow["who"],
                flow["category"],
                flow.get("server_name") or flow.get("dns_name") or "",
                flow.get("app") or "",
                flow["packets"],
                flow["bytes"],
                flow["why"],
            ])
    write_html(html_path, summary)
    return html_path


def keep_device(packets, address):
    """Keep only packets that touch one computer. Empty means keep all."""
    if not address:
        return packets
    from scapy.all import IP
    kept = [packet for packet in packets if IP in packet and address in (packet[IP].src, packet[IP].dst)]
    if not kept:
        raise SystemExit(f"No packets touched {address}. Check the address, or run without --device.")
    return kept


def print_summary(summary):
    metrics = summary["metrics"]
    print("\nNETWORK STATUS")
    print(f"  Packets: {metrics['packet_count']}")
    print(f"  Packets/sec: {metrics['packets_per_second']}")
    print(f"  Active talks: {len(summary.get('flows') or [])}")
    lookups = ", ".join(f"{item['name']} {item['ms']} ms" for item in summary.get("dns_times") or []) or "none timed"
    print(f"  Name lookups: {lookups}")
    print(f"  Repeated packets: {metrics.get('repeated_sequences', 0)}")
    print(f"  Resets: {metrics.get('resets', 0)}")
    print(f"  Apps: {', '.join(summary.get('apps') or []) or 'none named'}")
    print(f"  Devices: {len(summary.get('devices') or [])}")
    print(f"  Why it may be slow: {summary.get('why_slow')}")
    for item in summary.get("alerts") or []:
        print(f"  - {item}")
    print("\nBest guess by port")
    for name, count in sorted(summary["categories"].items(), key=lambda item: -item[1]):
        print(f"  {name}: {count}")
    print("\nConversations")
    for flow in summary["flows"][:12]:
        seen = flow.get("server_name") or flow.get("dns_name")
        extra = f"  name={seen}" if seen else ""
        if flow.get("app"):
            extra += f"  app={flow['app']}"
        print(f"  {flow['who']}  {flow['category']}  packets={flow['packets']} bytes={flow['bytes']}{extra}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read network traffic in plain language. Does not decrypt anything.")
    parser.add_argument("command", nargs="?", choices=["demo", "live", "watch", "pcap", "window", "check", "setup"], help="demo, live, watch, pcap, window, check, or setup")
    parser.add_argument("--seconds", type=int, default=15, help="Seconds for each watch round. Default: 15.")
    parser.add_argument("pcap_path", nargs="?", help="Capture file, used with: dpi pcap file.pcap")
    parser.add_argument("--iface", help="Live interface name, for example Wi-Fi.")
    parser.add_argument("--app", help="After the reading, keep only talks that matched this app, for example YouTube.")
    parser.add_argument("--count", type=int, default=80, help="Live packet count. Default: 80.")
    parser.add_argument("--out", default=None, help="Report folder. Live writes to live-output. Demo writes to dpi-output.")
    # Keep the old flags working.
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--pcap", help="Capture file.")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if args.command == "check":
        from dpi.doctor import check_computer, exe_ready
        for line in check_computer():
            print(line)
        print(exe_ready())
        return None
    if args.command == "setup":
        from dpi.doctor import check_computer, install_python_pieces
        print(install_python_pieces())
        for line in check_computer():
            print(line)
        print("Next: python DPI.py demo")
        print("Live, as Administrator: python DPI.py live --count 80")
        print("To make DPI.exe on Windows: double-click build_exe.bat")
        return None
    if args.command == "window":
        from dpi.gui import launch
        launch()
        return None
    if args.command == "pcap" or args.pcap:
        path = args.pcap_path or args.pcap
        if not path:
            parser.error("Give a capture file, for example: dpi pcap capture.pcap")
        packets = keep_device(load_pcap(path), args.device)
        source = f"pcap file {path}"
        summary = analyze(packets, source)
    elif args.command == "live" or args.live or args.iface:
        iface = args.iface or choose_live_interface()
        packets = keep_device(capture_live(iface, args.count), args.device)
        source = f"live capture on {iface}, the network this computer is using"
        if not packets:
            raise SystemExit(f"No packets were read on {iface}. Run this window as Administrator, install Npcap, and pick the Wi-Fi or Ethernet name.")
        summary = analyze(packets, source)
        linked = devices_on_link(iface)
        if linked:
            summary["devices"] = [{"address": address, "how": "answered on the local network"} for address in linked]
            summary["highlights"].insert(0, f"{len(linked)} device(s) answered on the local network: {', '.join(linked)}.")
        out_dir = args.out or "live-output"
    elif args.command == "watch":
        iface = args.iface or choose_live_interface()
        print(f"Watching {iface}. Press Ctrl+C to stop. The report refreshes each round.")
        print("Only do this on a network you are allowed to monitor.")
        collected = []
        out_dir = args.out or "live-output"
        try:
            while True:
                batch = capture_for_seconds(iface, args.seconds)
                if args.device:
                    from scapy.all import IP
                    batch = [packet for packet in batch if IP in packet and args.device in (packet[IP].src, packet[IP].dst)]
                collected.extend(batch)
                summary = analyze(collected, f"watch on {iface}, the network this computer is using")
                if args.app:
                    wanted = args.app.lower()
                    summary["flows"] = [flow for flow in summary["flows"] if wanted in (flow.get("app") or "").lower()]
                html_path = write_outputs(summary, out_dir)
                print(f"\nRound: {len(collected)} packets so far. Wrote {html_path}")
                print_summary(summary)
        except KeyboardInterrupt:
            print("\nStopped.")
            return summary if collected else None
    else:
        packets = build_demo_packets()
        source = "built-in demo (fake packets, not your network)"
        summary = analyze(packets, source)
        out_dir = args.out or "dpi-output"
    if args.command == "pcap" or args.pcap:
        out_dir = args.out or "dpi-output"
    if args.app:
        wanted = args.app.lower()
        summary["flows"] = [flow for flow in summary["flows"] if wanted in (flow.get("app") or "").lower()]
        summary["highlights"].insert(0, f"Filtered to the app name {args.app}. Other talks are hidden.")
    print_summary(summary)
    html_path = write_outputs(summary, out_dir)
    print(f"\nWrote {html_path}")
    return summary


if __name__ == "__main__":
    main()
