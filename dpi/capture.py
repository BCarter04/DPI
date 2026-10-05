"""Where the packets come from.

Copyright (c) 2023-2026 Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.

What it does now
    build_demo_packets() makes fake packets so the tool runs with no network.
    load_pcap() reads a saved capture.
    choose_live_interface() picks the connected card, not the loopback adapter.
    capture_live() listens until it has enough packets, or 30 seconds pass.

What it will do
    A later version can keep listening and refresh the report. It will still
    not decrypt the payload.
"""

def client_hello(server_name):
    """Minimal TLS ClientHello used only by the demo."""
    host = server_name.encode("ascii")
    server_entry = b"\x00" + len(host).to_bytes(2, "big") + host
    sni_body = len(server_entry).to_bytes(2, "big") + server_entry
    extensions = b"\x00\x00" + len(sni_body).to_bytes(2, "big") + sni_body
    ciphers = b"\x00\x2f\xc0\x2f"
    body = (
        b"\x03\x03"
        + b"\x11" * 32
        + b"\x00"
        + len(ciphers).to_bytes(2, "big") + ciphers
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big") + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def build_demo_packets():
    from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP

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
    add(IP(src="10.0.0.8", dst="93.184.216.34") / TCP(sport=51001, dport=443) / Raw(load=client_hello("www.example.com")), 0.08)
    add(IP(src="93.184.216.34", dst="10.0.0.8") / TCP(sport=443, dport=51001) / Raw(load=b"\x17\x03\x03" + b"\x00" * 40), 0.03)
    add(IP(src="10.0.0.8", dst="93.184.216.34") / TCP(sport=51001, dport=443) / Raw(load=b"\x17\x03\x03" + b"\xab" * 80), 0.05)
    add(IP(src="10.0.0.8", dst="203.0.113.10") / TCP(sport=51002, dport=22) / Raw(load=b"SSH-2.0-demo\r\n"), 0.1)
    add(IP(src="10.0.0.8", dst="203.0.113.50") / TCP(sport=51003, dport=443) / Raw(load=client_hello("cdn.example.net")), 0.2)
    add(IP(src="10.0.0.8", dst="203.0.113.80") / TCP(sport=51005, dport=443) / Raw(load=client_hello("rr3.googlevideo.com")), 0.1)
    add(IP(src="10.0.0.8", dst="203.0.113.81") / TCP(sport=51006, dport=443) / Raw(load=client_hello("ipv4-c002.nflxvideo.net")), 0.1)
    add(IP(src="10.0.0.8", dst="10.0.0.1") / UDP(sport=48000, dport=123) / Raw(load=b"\x1b" + b"\x00" * 47), 0.15)
    add(IP(src="10.0.0.8", dst="198.51.100.20") / TCP(sport=51004, dport=4444) / Raw(load=b"\x99" * 24), 0.12)
    return packets


def load_pcap(path):
    from scapy.all import rdpcap
    return list(rdpcap(path))


def list_interfaces():
    """Return interface names this computer can see."""
    from scapy.all import get_if_list
    return list(get_if_list())


def choose_live_interface():
    """Pick the network this computer is using, not the loopback adapter."""
    from scapy.all import conf, get_if_addr, get_if_list

    names = list(get_if_list())
    addresses = {}
    print("Interfaces this computer can see:")
    for name in names:
        try:
            addresses[name] = get_if_addr(name)
        except Exception:
            addresses[name] = ""
        print(f"  {name}  {addresses[name] or 'no address'}")

    def usable(name):
        low = name.lower()
        if "loopback" in low or low in {"lo", "lo0"}:
            return False
        return (addresses.get(name) or "") not in {"", "0.0.0.0", "127.0.0.1"}

    preferred = str(conf.iface)
    if preferred in addresses and usable(preferred):
        return preferred
    for name in names:
        if usable(name):
            return name
    for hint in ("wi-fi", "wifi", "wlan", "ethernet", "eth", "en0"):
        for name in names:
            if hint in name.lower() and "loopback" not in name.lower():
                return name
    raise SystemExit("No connected interface found. On Windows, install Npcap and run as Administrator.")


def capture_live(interface, count):
    """Read a set number of packets, then stop. This is the short live check."""
    from scapy.all import sniff
    print(f"Listening on {interface} for {count} packets.")
    print("Only do this on a network you are allowed to monitor. Browse to create traffic.")
    return sniff(iface=interface, count=count, timeout=30)


def capture_for_seconds(interface, seconds):
    """Keep reading for a few seconds. Used by watch mode, which repeats this."""
    from scapy.all import sniff
    return sniff(iface=interface, timeout=seconds)
