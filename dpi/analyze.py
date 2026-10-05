"""Turn packets into plain-language facts.

Copyright (c) 2023-2026 Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.

What it does now
    Guesses a category from the port, groups both directions into one
    conversation, reads a DNS name or TLS server name when it is visible,
    and builds a short handshake fingerprint. The fingerprint is the shape
    of the handshake, not the page.

What it will do
    Later it can compare size and timing across runs. It will not grow into
    a decryptor. Encrypted contents stay encrypted.
"""

from collections import defaultdict

from dpi.apps import guess_app
from dpi.devices import devices_in_packets
from dpi.health import dns_facts, tcp_facts

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
    for ports, name, sentence in PORT_GUIDE:
        if port in ports:
            return name, sentence
    return "Other", f"{transport} port {port} is not in the short well-known list."


def read_server_name(payload):
    data = bytes(payload)
    if len(data) < 11 or data[0] != 0x16 or data[5] != 0x01:
        return None, None
    try:
        index = 43
        session_len = data[index]
        index += 1 + session_len
        cipher_len = int.from_bytes(data[index:index + 2], "big")
        ciphers = data[index + 2:index + 2 + cipher_len]
        index += 2 + cipher_len
        comp_len = data[index]
        index += 1 + comp_len
        if index + 2 > len(data):
            return None, None
        ext_len = int.from_bytes(data[index:index + 2], "big")
        index += 2
        end = min(len(data), index + ext_len)
        types = []
        name = None
        while index + 4 <= end:
            ext_type = int.from_bytes(data[index:index + 2], "big")
            ext_size = int.from_bytes(data[index + 2:index + 4], "big")
            ext_data = data[index + 4:index + 4 + ext_size]
            types.append(ext_type)
            if ext_type == 0 and len(ext_data) >= 5 and name is None:
                name_len = int.from_bytes(ext_data[3:5], "big")
                name = ext_data[5:5 + name_len].decode("utf-8", "replace")
            index += 4 + ext_size
        cipher_text = "-".join(f"{int.from_bytes(ciphers[i:i+2], 'big'):04x}" for i in range(0, len(ciphers) - 1, 2))
        fingerprint = f"ciphers:{cipher_text};ext:{','.join(str(item) for item in types)}"
        return name, fingerprint
    except (IndexError, ValueError):
        return None, None


def read_dns_name(packet):
    try:
        from scapy.all import DNS
        if DNS in packet and packet[DNS].qd is not None:
            name = packet[DNS].qd.qname
            if isinstance(name, bytes):
                name = name.decode("utf-8", "replace")
            return str(name).rstrip(".")
    except Exception:
        return None
    return None


def _endpoints(packet):
    from scapy.all import IP, IPv6, TCP, UDP
    if IP in packet:
        src, dst = packet[IP].src, packet[IP].dst
    elif IPv6 in packet:
        src, dst = packet[IPv6].src, packet[IPv6].dst
    else:
        return None
    if TCP in packet:
        return src, dst, int(packet[TCP].sport), int(packet[TCP].dport), "TCP", bytes(packet[TCP].payload)
    if UDP in packet:
        return src, dst, int(packet[UDP].sport), int(packet[UDP].dport), "UDP", bytes(packet[UDP].payload)
    proto = PROTO_NAMES.get(packet[IP].proto, "Other") if IP in packet else "Other"
    return src, dst, 0, 0, proto, b""


def analyze(packets, source):
    from datetime import datetime

    categories = defaultdict(int)
    protocols = defaultdict(int)
    talkers = defaultdict(int)
    flows = {}
    names = set()
    apps = set()
    quic = 0
    resets = 0
    repeats = 0
    dns_problems = []
    seen_seq = set()
    payload_bytes = 0
    sizes = []
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
        sizes.append(len(payload))
        protocols[transport] += 1
        talkers[src] += len(payload)
        talkers[dst] += len(payload)
        left, right = explain_port(sport, transport), explain_port(dport, transport)
        if right[0] != "Other":
            category, sentence = right
        elif left[0] != "Other":
            category, sentence = left
        else:
            category, sentence = right
        categories[category] += 1
        if transport == "UDP" and 443 in (sport, dport):
            quic += 1
            categories["Possible QUIC (HTTP/3)"] += 1
            category = "Possible QUIC (HTTP/3)"
            sentence = "UDP port 443 is often QUIC, used by some video apps. The video stays hidden."
        facts = tcp_facts(packet)
        if facts:
            if "RST" in facts["flags"]:
                resets += 1
            mark = (src, sport, dst, dport, facts["seq"])
            if facts["seq"] and mark in seen_seq:
                repeats += 1
            seen_seq.add(mark)
        dns = dns_facts(packet)
        if dns and dns["problem"]:
            dns_problems.append(f"{dns['name']}: {dns['problem']}")
        server_name, fingerprint = read_server_name(payload)
        dns_name = read_dns_name(packet)
        if dns_name:
            names.add(dns_name)
        key = tuple(sorted([(src, sport), (dst, dport)])) + (transport,)
        flow = flows.setdefault(key, {
            "who": f"{src}:{sport} ↔ {dst}:{dport}",
            "category": category,
            "why": sentence,
            "packets": 0,
            "bytes": 0,
            "server_name": None,
            "fingerprint": None,
            "dns_name": None,
            "app": None,
        })
        flow["packets"] += 1
        flow["bytes"] += len(payload)
        if server_name:
            flow["server_name"] = server_name
            flow["category"] = "Encrypted web (HTTPS)"
            flow["why"] = f"The handshake named {server_name}. The page contents are still hidden."
            names.add(server_name)
        if fingerprint:
            flow["fingerprint"] = fingerprint
        if dns_name:
            flow["dns_name"] = dns_name
        seen = flow.get("server_name") or flow.get("dns_name")
        app, confidence = guess_app(seen)
        if app:
            flow["app"] = app
            flow["confidence"] = confidence
            apps.add(app)
            flow["why"] = f"The visible name matches {app}. Confidence is high. The page or video is still hidden."

    duration = (max(times) - min(times)) if len(times) >= 2 else 0.0
    window = duration if duration > 0 else None
    flow_list = sorted(flows.values(), key=lambda item: -item["bytes"])
    top_talkers = sorted(talkers.items(), key=lambda item: -item[1])[:5]
    other = categories.get("Other", 0)
    highlights = []
    if apps:
        highlights.append("Apps recognised from visible names: " + ", ".join(sorted(apps)) + ".")
    else:
        highlights.append("No YouTube, Netflix, Google, or other listed app name was visible.")
    local_devices = devices_in_packets(packets)
    if local_devices:
        highlights.append(f"{len(local_devices)} local device(s) were active in this capture: {', '.join(local_devices)}.")
    else:
        highlights.append("No local device address was seen in this capture.")
    if names:
        highlights.append("Visible names: " + ", ".join(sorted(names)) + ".")
    else:
        highlights.append("No site or lookup name was visible. That is normal if the handshake was missed.")
    if other:
        highlights.append(f"{other} packets used a port this tool does not recognise. A port is only a hint.")
    if flow_list:
        busiest = flow_list[0]
        highlights.append(f"Busiest conversation: {busiest['who']} ({busiest['bytes']} bytes).")
    if sizes:
        small = sum(1 for size in sizes if size < 100)
        large = sum(1 for size in sizes if size >= 500)
        highlights.append(
            f"Payload sizes ran from {min(sizes)} to {max(sizes)} bytes. "
            f"{small} were under 100 bytes and {large} were 500 bytes or more."
        )
    if len(times) >= 4:
        gaps = [times[i] - times[i - 1] for i in range(1, len(times))]
        short = sum(1 for gap in gaps if gap < 0.05)
        if short >= max(3, len(gaps) // 2):
            highlights.append("Many packets arrived close together. That often means a busy download or a burst of traffic, not a slow lookup.")
    if quic:
        highlights.append(f"{quic} packet(s) used UDP port 443. That is often QUIC, not ordinary web. The content is still hidden.")
    if repeats:
        highlights.append(f"{repeats} repeated TCP sequence number(s). That can mean a lost packet was sent again. It is a hint, not proof of the cause.")
    if resets:
        highlights.append(f"{resets} connection(s) were reset. A reset means one side closed the talk abruptly.")
    if dns_problems:
        highlights.append("DNS problems: " + "; ".join(dns_problems[:5]) + ".")
    notes = [
        "Nothing was decrypted. Encrypted page contents stay encrypted.",
        "A port label is a hint. Many apps share port 443.",
        "An app name is a match on the visible site name, not proof of which video or search was used.",
        "A repeated sequence number is a simple loss hint. A short capture can miss the real cause.",
        "A device count is who talked, or who answered on the local network. A silent device is not listed.",
    ]
    return {
        "source": source,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "categories": dict(categories),
        "flows": flow_list,
        "names": sorted(names),
        "apps": sorted(apps),
        "devices": [{"address": address, "how": "seen in this capture"} for address in local_devices],
        "talkers": [{"address": address, "bytes": count} for address, count in top_talkers],
        "highlights": highlights,
        "metrics": {
            "packet_count": len(packets),
            "duration_seconds": round(duration, 3),
            "total_payload_bytes": payload_bytes,
            "packets_per_second": round(len(packets) / window, 2) if window else None,
            "bytes_per_second": round(payload_bytes / window, 2) if window else None,
            "protocol_names": dict(protocols),
            "repeated_sequences": repeats,
            "resets": resets,
            "quic_packets": quic,
        },
        "notes": notes,
    }
