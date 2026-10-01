"""Front door for the program.

What it does now
    Reads the command, gets packets, prints a short reading, and writes
    report.html, summary.json, and conversations.csv.

What it will do
    The same functions can sit behind a window later. The window should
    call main(), not copy this logic.
"""

import argparse
import json
import os
import sys

from dpi.analyze import analyze
from dpi.capture import build_demo_packets, capture_live, choose_live_interface, load_pcap
from dpi.report import write_html


def write_outputs(summary, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "summary.json")
    csv_path = os.path.join(out_dir, "conversations.csv")
    html_path = os.path.join(out_dir, "report.html")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
    with open(csv_path, "w", encoding="utf-8") as handle:
        handle.write("who,category,name,packets,bytes,why\n")
        for flow in summary["flows"]:
            name = flow.get("server_name") or flow.get("dns_name") or ""
            why = flow["why"].replace('"', "'")
            handle.write(f"\"{flow['who']}\",\"{flow['category']}\",\"{name}\",{flow['packets']},{flow['bytes']},\"{why}\"\n")
    write_html(html_path, summary)
    return html_path


def print_summary(summary):
    metrics = summary["metrics"]
    print("\nDPI reading")
    print("-----------")
    print(f"Source: {summary['source']}")
    print(f"Packets: {metrics['packet_count']}")
    print(f"Time span: {metrics['duration_seconds']} seconds")
    print(f"Payload bytes: {metrics['total_payload_bytes']}")
    print("\nWhat stands out")
    for item in summary["highlights"]:
        print(f"  - {item}")
    print("\nBest guess by port")
    for name, count in sorted(summary["categories"].items(), key=lambda item: -item[1]):
        print(f"  {name}: {count}")
    print("\nConversations")
    for flow in summary["flows"][:12]:
        seen = flow.get("server_name") or flow.get("dns_name")
        extra = f"  name={seen}" if seen else ""
        print(f"  {flow['who']}  {flow['category']}  packets={flow['packets']} bytes={flow['bytes']}{extra}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read network traffic in plain language. Does not decrypt anything.")
    parser.add_argument("command", nargs="?", choices=["demo", "live", "pcap"], help="demo, live, or pcap")
    parser.add_argument("pcap_path", nargs="?", help="Capture file, used with: dpi pcap file.pcap")
    parser.add_argument("--iface", help="Live interface name, for example Wi-Fi.")
    parser.add_argument("--count", type=int, default=80, help="Live packet count. Default: 80.")
    parser.add_argument("--out", default="dpi-output", help="Report folder.")
    # Keep the old flags working.
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--pcap", help="Capture file.")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if args.command == "pcap" or args.pcap:
        path = args.pcap_path or args.pcap
        if not path:
            parser.error("Give a capture file, for example: dpi pcap capture.pcap")
        packets = load_pcap(path)
        source = f"pcap file {path}"
    elif args.command == "live" or args.live or args.iface:
        iface = args.iface or choose_live_interface()
        packets = capture_live(iface, args.count)
        source = f"live capture on {iface}"
    else:
        packets = build_demo_packets()
        source = "built-in demo (fake packets, not your network)"
    summary = analyze(packets, source)
    print_summary(summary)
    html_path = write_outputs(summary, args.out)
    print(f"\nWrote {html_path}")
    return summary


if __name__ == "__main__":
    main()
