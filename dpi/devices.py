"""Count devices seen on the local network.

Copyright (c) 2023-2026 Oluwatobiloba Benjamin Ogungbangbe. All rights reserved.

What it does now
    Counts private addresses in the capture. Those are devices that talked
    during this check. On a live run it also asks the local network who is
    awake, using a normal ARP request on that subnet only.

What it will do
    It can later show a name for a device, such as a phone or a laptop.
    It will not scan the public internet, and it will not claim a silent
    device is absent. A device that does not answer is simply not listed.
"""

import ipaddress


def is_local(address):
    """True for a home or office address: 10.x, 172.16–31.x, or 192.168.x."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if ip.version != 4 or ip.is_loopback:
        return False
    return ip in ipaddress.ip_network("10.0.0.0/8") or ip in ipaddress.ip_network("172.16.0.0/12") or ip in ipaddress.ip_network("192.168.0.0/16")


def role_for(address):
    """A plain guess. An address ending in .1 is often the router. It is not a name."""
    if str(address).endswith(".1"):
        return "Likely router"
    return "Computer that talked"


def devices_in_packets(packets):
    """Private addresses that sent or received a packet in this capture."""
    from scapy.all import IP
    found = set()
    for packet in packets:
        if IP not in packet:
            continue
        for address in (packet[IP].src, packet[IP].dst):
            if is_local(address):
                found.add(address)
    return sorted(found)


def devices_on_link(interface):
    """Ask the local subnet which devices are active. Live checks only."""
    from scapy.all import conf, get_if_addr
    try:
        own = get_if_addr(interface)
    except Exception:
        return []
    if not is_local(own):
        return []
    network = ipaddress.ip_network(f"{own}/24", strict=False)
    try:
        from scapy.all import arping
        answered, _ = arping(str(network), iface=interface, timeout=2, verbose=0)
    except Exception:
        return []
    found = {own}
    for _, reply in answered:
        address = reply.psrc
        if is_local(address):
            found.add(address)
    return sorted(found)
