"""Plain-language health checks. No decryption.

Copyright (c) 2023-2026 Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.

What this file does
    Looks at TCP flags and DNS replies that are already visible.
    A retransmission here means the same TCP sequence number was seen twice.
    That is a hint of loss or a busy link, not proof of the cause.
    UDP port 443 is labelled as possible QUIC, which is how some apps send
    video without using normal TCP.

What it will do later
    A longer capture can turn these hints into a health score.
    It will still not read the page or the video.
"""

DNS_PROBLEMS = {2: "server failed", 3: "name not found", 5: "refused"}


def tcp_facts(packet):
    """Return flag names and sequence number, or None if this is not TCP."""
    from scapy.all import TCP
    if TCP not in packet:
        return None
    tcp = packet[TCP]
    flags = []
    if tcp.flags.S:
        flags.append("SYN")
    if tcp.flags.A:
        flags.append("ACK")
    if tcp.flags.R:
        flags.append("RST")
    if tcp.flags.F:
        flags.append("FIN")
    return {"flags": flags, "seq": int(tcp.seq)}


def dns_facts(packet):
    """Return the looked-up name and whether the reply failed."""
    try:
        from scapy.all import DNS
    except Exception:
        return None
    if DNS not in packet or packet[DNS].qd is None:
        return None
    try:
        name = packet[DNS].qd.qname
        if isinstance(name, bytes):
            name = name.decode("utf-8", "replace")
        name = str(name).rstrip(".")
        reply = int(packet[DNS].qr) == 1
        problem = DNS_PROBLEMS.get(int(packet[DNS].rcode)) if reply else None
        return {"name": name, "reply": reply, "problem": problem}
    except (IndexError, AttributeError, TypeError):
        return None
