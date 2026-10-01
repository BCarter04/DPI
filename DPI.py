"""
DPI — a small, readable look at network traffic.

What this program does
----------------------
It reads packets (from a demo, a .pcap file, or a live interface) and
answers three beginner questions:

1. What kind of traffic is this?  (a guess from the port)
2. Who was talking to whom?       (conversations, not single packets)
3. What can we see without decrypting?  (sizes, timing, TLS server name)

What it does not do
-------------------
It does not decrypt HTTPS, break TLS, or bypass a network filter.
Encrypted payloads stay encrypted. Only run a live capture on a network
you are allowed to monitor.
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

from report import write_html

# Well-known ports. The label is a guess, not a fact.
# Each entry is: ports, category name, one-sentence explanation.
PORT_GUIDE = [
    ({80, 8080, 8000}, "Web, not encrypted", "Port 80 is the old web port. The page text can be visible."),
    ({443, 8443}, "Encrypted web (HTTPS)", "Port 443 is the usual HTTPS port. The page itself stays encrypted."),
    ({22}, "Remote login (SSH)", "Port 22 is usually a secure shell login."),
    ({53}, "Name lookup (DNS)", "Port 53 turns a name like example.com into an address."),
    ({25, 465, 587}, "Email", "These ports are used to send mail."),
    ({20, 21}, "File transfer (FTP)", "Ports 20 and 21 are the old file-transfer ports."),
    ({67, 68}, "Address setup (DHCP)", "These ports hand a computer its local address."),
    ({123}, "Clock sync (NTP)", "Port 123 is used to check the time."),
    ({137, 138, 139, 445}, "File sharing", "These ports are used by Windows-style file sharing."),
    ({5060, 5061}, "Calls (VoIP)", "These ports are used by some internet phone calls."),
    ({1194}, "VPN", "Port 1194 is the usual OpenVPN port."),
    ({1935}, "Video stream", "Port 1935 is an older video-streaming port."),
]

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def explain_port(port, transport):
    """Return (category, plain sentence) for a port number."""
    for ports, name, sentence in PORT_GUIDE:
        if port in ports:
            return name, sentence
    return "Other", f"{transport} port {port} is not in the small well-known list, so it stays Other."


def client_hello(server_name):
    """Build a minimal TLS ClientHello that carries a server name.

    This is only used to make the demo realistic. It is not a connection.
    """
    host = server_name.encode("ascii")
    server_entry = b"\x00" + len(host).to_bytes(2, "big") + host
    sni_body = len(server_entry).to_bytes(2, "big") + server_entry
    extensions = b"\x00\x00" + len(sni_body).to_bytes(2, "big") + sni_body
    ciphers = b"\x00\x2f\xc0\x2f"  # two cipher suites
    body = (
        b"\x03\x03"
        + b"\x11" * 32
        + b"\x00"  # empty session id
        + len(ciphers).to_bytes(2, "big") + ciphers
        + b"\x01\x00"  # one compression method: null
        + len(extensions).to_bytes(2, "big") + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def read_server_name(payload):
    """Return the TLS server name if this payload is a ClientHello, else None.

    The server name (SNI) sits in the handshake, before encryption starts.
    Newer privacy features can hide it. If it is hidden, this returns None.
    """
    data = bytes(payload)
    if len(data) < 11 or data[0] != 0x16 or data[5] != 0x01:
        return None
    try:
        index = 9  # handshake header (4) starts at byte 5; version+random follow
        index += 2 + 32  # client version + random
        session_len = data[index]
        index += 1 + session_len
        cipher_len = int.from_bytes(data[index:index + 2], "big")
        index += 2 + cipher_len
        comp_len = data[index]
        index += 1 + comp_len
        if index + 2 > len(data):
            return None
        ext_len = int.from_bytes(data[index:index + 2], "big")
        index += 2
        end = min(len(data), index + ext_len)
        while index + 4 <= end:
            ext_type = int.from_bytes(data[index:index + 2], "big")
            ext_size = int.from_bytes(data[index + 2:index + 4], "big")
            ext_data = data[index + 4:index + 4 + ext_size]
            if ext_type == 0 and len(ext_data) >= 5:
                name_len = int.from_bytes(ext_data[3:5], "big")
                return ext_data[5:5 + name_len].decode("utf-8", "replace")
            index += 4 + ext_size
    except (IndexError, ValueError):
        return None
    return None


def build_demo_packets():
    """Make a tiny fake capture so the tool can be shown with no network card."""
    from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR

    packets = []
    clock = 1_700_000_000.0

    def add(packet, delay):
        nonlocal clock
        clock += delay
        packet.time = clock
        packets.append(packet)

    add(IP(src="10.0.0.8", dst="1.1.1.1") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")), 0.01)
    add(IP(src="1.1.1.1", dst="10.0.0.8") / UDP(sport=53, dport=53000) / Raw(load=b"demo-dns-reply"), 0.02)
    add(IP(src="10.0.0.8", dst="93.184.216.34") / TCP(sport=51000, dport=80) / Raw(load=b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n"), 0.05)
    add(IP(src="93.184.216.34", dst="10.0.0.8") / TCP(sport=80, dport=51000) / Raw(load=b"HTTP/1.1 200 OK\r\n\r\nhello"), 0.04)
    hello = client_hello("www.example.com")
    add(IP(src="10.0.0.8", dst="93.184.216.34") / TCP(sport=51001, dport=443) / Raw(load=hello), 0.08)
    add(IP(src="93.184.216.34", dst="10.0.0.8") / TCP(sport=443, dport=51001) / Raw(load=b"\x17\x03\x03" + b"\x00" * 40), 0.03)
    add(IP(src="10.0.0.8", dst="93.184.216.34") / TCP(sport=51001, dport=443) / Raw(load=b"\x17\x03\x03" + b"\xab" * 80), 0.05)
    add(IP(src="10.0.0.8", dst="203.0.113.10") / TCP(sport=51002, dport=22) / Raw(load=b"SSH-2.0-demo\r\n"), 0.1)
    add(IP(src="10.0.0.8", dst="203.0.113.50") / TCP(sport=51003, dport=443) / Raw(load=client_hello("cdn.example.net")), 0.2)
    add(IP(src="10.0.0.8", dst="10.0.0.1") / UDP(sport=48000, dport=123) / Raw(load=b"\x1b" + b"\x00" * 47), 0.15)
    add(IP(src="10.0.0.8", dst="198.51.100.20") / TCP(sport=51004, dport=4444) / Raw(load=b"\x99" * 24), 0.12)
    return packets


def load_pcap(path):
    from scapy.all import rdpcap
    return list(rdpcap(path))


def capture_live(interface, count):
    from scapy.all import sniff
    print(f"Listening on {interface} for {count} packets.")
    print("Use a network you are allowed to monitor. Browse or generate some traffic.")
    return sniff(iface=interface, count=count)


def _endpoints(packet):
    """Return src, dst, sport, dport, transport name, or None if not IP/TCP/UDP."""
    from scapy.all import IP, TCP, UDP, IPv6

    if IP in packet:
        src, dst = packet[IP].src, packet[IP].dst
    elif IPv6 in packet:
        src, dst = packet[IPv6].src, packet[IPv6].dst
    else:
        return None
    if TCP in packet:
        return src, dst, packet[TCP].sport, packet[TCP].dport, "TCP", bytes(packet[TCP].payload)
    if UDP in packet:
        return src, dst, packet[UDP].sport, packet[UDP].dport, "UDP", bytes(packet[UDP].payload)
    return src, dst, 0, 0, PROTO_NAMES.get(packet[IP].proto, "Other") if IP in packet else "Other", b""


def analyze(packets, source):
    """Turn packets into categories, conversations, and honest speed numbers."""
    categories = defaultdict(int)
    protocol_counts = defaultdict(int)
    flows = {}
    payload_bytes = 0
    times = []

    for packet in packets:
        stamp = float(getattr(packet, "time", 0) or 0)
        if stamp:
            times.append(stamp)
        ends = _endpoints(packet)
        if ends is None:
            categories["Not IP"] += 1
            continue
        src, dst, sport, dport, transport, payload = ends
        payload_bytes += len(payload)
        protocol_counts[transport] += 1

        # Guess from the server-side port when one side is well known.
        left = explain_port(sport, transport)
        right = explain_port(dport, transport)
        if right[0] != "Other":
            category, sentence = right
            server_port = dport
        elif left[0] != "Other":
            category, sentence = left
            server_port = sport
        else:
            category, sentence = right
            server_port = dport
        categories[category] += 1

        server_name = read_server_name(payload)
        key = tuple(sorted([(src, sport), (dst, dport)])) + (transport,)
        flow = flows.setdefault(key, {
            "who": f"{src}:{sport} ↔ {dst}:{dport}",
            "category": category,
            "why": sentence,
            "server_port": server_port,
            "packets": 0,
            "bytes": 0,
            "server_name": None,
        })
        flow["packets"] += 1
        flow["bytes"] += len(payload)
        if server_name:
            flow["server_name"] = server_name
            flow["category"] = "Encrypted web (HTTPS)"
            flow["why"] = f"The handshake named {server_name}. The page contents are still hidden."

    if len(times) >= 2:
        duration = max(times) - min(times)
    else:
        duration = 0.0
    # Avoid dividing by zero on a one-packet capture. Say so in the notes.
    speed_window = duration if duration > 0 else None
    packet_count = len(packets)
    metrics = {
        "packet_count": packet_count,
        "duration_seconds": round(duration, 3),
        "total_payload_bytes": payload_bytes,
        "packets_per_second": round(packet_count / speed_window, 2) if speed_window else None,
        "bytes_per_second": round(payload_bytes / speed_window, 2) if speed_window else None,
        "protocol_names": dict(protocol_counts),
    }

    named = [flow for flow in flows.values() if flow["server_name"]]
    notes = [
        "A port label is a hint. Port 443 usually means encrypted web, but other apps use it too.",
        "Speed numbers use the time from the first packet to the last. They are not a fake 1-second window.",
        "Server names come only from the TLS handshake. The tool never decrypts the payload.",
    ]
    if not speed_window:
        notes.append("Only one timestamp was available, so packets-per-second is left blank instead of guessed.")
    if named:
        names = ", ".join(sorted({flow["server_name"] for flow in named}))
        notes.append(f"Visible server names in this capture: {names}.")
    else:
        notes.append("No TLS server name was visible. That is normal if the handshake was missed or hidden.")

    flow_list = sorted(flows.values(), key=lambda item: -item["bytes"])
    return {
        "source": source,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "categories": dict(categories),
        "flows": flow_list,
        "metrics": metrics,
        "notes": notes,
    }


def print_summary(summary):
    """Print a short reading of the analysis."""
    metrics = summary["metrics"]
    print()
    print("DPI reading")
    print("-----------")
    print(f"Source: {summary['source']}")
    print(f"Packets: {metrics['packet_count']}")
    print(f"Time span: {metrics['duration_seconds']} seconds")
    print(f"Payload bytes: {metrics['total_payload_bytes']}")
    pps = metrics["packets_per_second"]
    print(f"Packets per second: {pps if pps is not None else 'not enough timestamps'}")
    print()
    print("Best guess by port")
    for name, count in sorted(summary["categories"].items(), key=lambda item: -item[1]):
        print(f"  {name}: {count}")
    print()
    print("Conversations")
    for flow in summary["flows"]:
        extra = f"  name={flow['server_name']}" if flow["server_name"] else ""
        print(f"  {flow['who']}  {flow['category']}  packets={flow['packets']} bytes={flow['bytes']}{extra}")
        print(f"    {flow['why']}")
    print()
    print("Plain notes")
    for note in summary["notes"]:
        print(f"  - {note}")


def write_outputs(summary, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "summary.json")
    csv_path = os.path.join(out_dir, "conversations.csv")
    html_path = os.path.join(out_dir, "report.html")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
    with open(csv_path, "w", encoding="utf-8") as handle:
        handle.write("who,category,server_name,packets,bytes,why\n")
        for flow in summary["flows"]:
            why = flow["why"].replace('"', "'")
            name = flow["server_name"] or ""
            handle.write(
                f"\"{flow['who']}\",\"{flow['category']}\",\"{name}\","
                f"{flow['packets']},{flow['bytes']},\"{why}\"\n"
            )
    write_html(html_path, summary)
    return json_path, csv_path, html_path


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Read network traffic in plain language. Does not decrypt anything."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--demo", action="store_true", help="Analyze a built-in fake capture. No network card needed.")
    source.add_argument("--pcap", help="Analyze a .pcap or .pcapng file.")
    source.add_argument("--iface", help="Capture live on this interface, for example Wi-Fi or eth0.")
    parser.add_argument("--count", type=int, default=100, help="How many live packets to read. Default: 100.")
    parser.add_argument("--out", default="dpi-output", help="Folder for the HTML, JSON, and CSV report.")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.pcap:
        packets = load_pcap(args.pcap)
        source = f"pcap file {args.pcap}"
    elif args.iface:
        packets = capture_live(args.iface, args.count)
        source = f"live capture on {args.iface}"
    else:
        # Default is the demo so a double-click or a bare run still shows something.
        packets = build_demo_packets()
        source = "built-in demo (fake packets, not your network)"
    summary = analyze(packets, source)
    print_summary(summary)
    json_path, csv_path, html_path = write_outputs(summary, args.out)
    print()
    print(f"Wrote {html_path}")
    print(f"Wrote {json_path}")
    print(f"Wrote {csv_path}")
    return summary


if __name__ == "__main__":
    main()
