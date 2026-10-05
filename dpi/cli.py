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


def print_summary(summary):
    metrics = summary["metrics"]
    print("\nDPI reading")
    print("-----------")
    print(f"Source: {summary['source']}")
    print(f"Packets: {metrics['packet_count']}")
    print(f"Local devices active: {len(summary.get('devices') or [])}")
    print(f"Time span: {metrics['duration_seconds']} seconds")
    print(f"Payload bytes: {metrics['total_payload_bytes']}")
    print("\nWhat stands out")
    for item in summary["highlights"]:
        print(f"  - {item}")
    print("\nWarnings")
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
    parser.add_argument("command", nargs="?", choices=["demo", "live", "watch", "pcap", "window"], help="demo, live, watch, pcap, or window")
    parser.add_argument("--seconds", type=int, default=15, help="Seconds for each watch round. Default: 15.")
    parser.add_argument("pcap_path", nargs="?", help="Capture file, used with: dpi pcap file.pcap")
    parser.add_argument("--iface", help="Live interface name, for example Wi-Fi.")
    parser.add_argument("--count", type=int, default=80, help="Live packet count. Default: 80.")
    parser.add_argument("--out", default=None, help="Report folder. Live writes to live-output. Demo writes to dpi-output.")
    # Keep the old flags working.
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--pcap", help="Capture file.")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if args.command == "window":
        from dpi.gui import launch
        launch()
        return None
    if args.command == "pcap" or args.pcap:
        path = args.pcap_path or args.pcap
        if not path:
            parser.error("Give a capture file, for example: dpi pcap capture.pcap")
        packets = load_pcap(path)
        source = f"pcap file {path}"
        summary = analyze(packets, source)
    elif args.command == "live" or args.live or args.iface:
        iface = args.iface or choose_live_interface()
        packets = capture_live(iface, args.count)
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
                collected.extend(batch)
                summary = analyze(collected, f"watch on {iface}, the network this computer is using")
                html_path = write_outputs(summary, out_dir)
                print(f"\nRound: {len(collected)} packets so far. Wrote {html_path}")
                for item in summary.get("alerts") or []:
                    print(f"  - {item}")
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
    print_summary(summary)
    html_path = write_outputs(summary, out_dir)
    print(f"\nWrote {html_path}")
    return summary


if __name__ == "__main__":
    main()
