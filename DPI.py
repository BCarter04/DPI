from scapy.all import sniff, TCP, UDP, IP
from collections import defaultdict

captured_packets = []  # Global list to store captured packets

def packet_capture(packet):
    """
    Callback function to capture network packets.
    """
    global captured_packets
    captured_packets.append(packet)

def start_packet_capture(interface="wlan0", count=100):
    """
    Start capturing network packets.

    Parameters:
        - interface: The network interface to capture packets from (e.g., "wlan0").
                     Default is "eth0".
        - count: The number of packets to capture. Default is 100.

    Note: This function runs indefinitely until the specified number of packets are captured.
    """
    print(f"Starting packet capture on interface '{interface}'...")
    print(f"\nEnsure there is traffic over your Wifi. You can browse or do something else that will transfer network traffic.\n\n")

    sniff(iface=interface, prn=packet_capture, count=count)


def basic_dpi(captured_packets):
    """
    Basic Deep Packet Inspection function to identify protocols and perform traffic analysis.

    Parameters:
        - captured_packets: List of captured packets for analysis.

    Returns:
        - protocol_counts: A dictionary containing the counts of each identified protocol.
        - traffic_metrics: A dictionary containing basic traffic metrics.
    """
    protocol_counts = defaultdict(int)
    total_bytes_transferred = 0

    for packet in captured_packets:
        if IP in packet:
            ip_layer = packet[IP]
            protocol_counts[ip_layer.proto] += 1

            if TCP in packet:
                total_bytes_transferred += len(packet[TCP].payload)
            elif UDP in packet:
                total_bytes_transferred += len(packet[UDP].payload)

    # Calculate total packet count
    total_packet_count = sum(protocol_counts.values())

    # Calculate packets per second (PPS) assuming the capture time is 1 second
    packets_per_second = total_packet_count

    # Calculate bytes per second (BPS) assuming the capture time is 1 second
    bytes_per_second = total_bytes_transferred

    traffic_metrics = {
        "Total Packet Count": total_packet_count,
        "Total Bytes Transferred": total_bytes_transferred,
        "Packets per Second (PPS)": packets_per_second,
        "Bytes per Second (BPS)": bytes_per_second,
        "Protocol Counts": dict(protocol_counts)
    }

    return protocol_counts, traffic_metrics

def protocol_identification_and_classification(captured_packets):
    """
    Identify major protocols and classify them into application categories.

    Parameters:
        - captured_packets: List of captured packets for analysis.

    Returns:
        - application_categories: A dictionary containing the counts of packets for each application category.
    """
    application_categories = defaultdict(int)
    other_ports = set()

    for packet in captured_packets:
        if IP in packet:
            ip_layer = packet[IP]
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport

                if src_port == 80 or dst_port == 80 or src_port == 8080:
                    application_categories["Unsecure Web Browsing"] += 1
                elif src_port == 443 or dst_port == 443:
                    application_categories["Secure Web Browsing"] += 1
                elif src_port == 25 or dst_port == 25 or src_port == 587 or dst_port == 587:
                    application_categories["Email"] += 1
                elif src_port == 53 or dst_port == 53:
                    application_categories["Domain Resolution"] += 1
                elif src_port == 21 or dst_port == 21 or src_port == 20 or dst_port == 20:
                    application_categories["FTP"] += 1
                elif src_port == 5060 or dst_port == 5060:
                    application_categories["VoIP"] += 1
                elif src_port == 22 or dst_port == 22:
                    application_categories["SSH"] += 1
                elif src_port == 137 or dst_port == 137 or src_port == 138 or dst_port == 138 or src_port == 445 or dst_port == 445:
                    application_categories["File Sharing"] += 1
                elif src_port == 80 or dst_port == 80 or src_port == 8080:
                    application_categories["Web Browsing"] += 1
                elif src_port == 443 or dst_port == 443:
                    application_categories["Secure Web Browsing"] += 1
                elif src_port == 5060 or dst_port == 5060 or src_port == 5061 or dst_port == 5061:
                    application_categories["VoIP"] += 1
                elif src_port == 1194 or dst_port == 1194:
                    application_categories["VPN"] += 1
                elif src_port == 1935 or dst_port == 1935:
                    application_categories["Video Streaming"] += 1
                else:
                    application_categories["Other"] += 1
                    other_ports.add(src_port)
                    other_ports.add(dst_port)
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

                if src_port == 53 or dst_port == 53:
                    application_categories["Domain Resolution"] += 1
                elif src_port == 67 or dst_port == 67 or src_port == 68 or dst_port == 68:
                    application_categories["DHCP"] += 1
                elif src_port == 123 or dst_port == 123:
                    application_categories["NTP"] += 1
                elif src_port == 1194 or dst_port == 1194:
                    application_categories["VPN"] += 1
                else:
                    application_categories["Other"] += 1
                    other_ports.add(src_port)
                    other_ports.add(dst_port)

    return application_categories, other_ports

if __name__ == "__main__":
    start_packet_capture(interface="Wi-Fi", count=100)
    application_categories, other_ports = protocol_identification_and_classification(captured_packets)
    
    
    # Print identified application categories
    print("*********************************************************")
    print("NETWORK TRAFFIC CLASSIFICATION BASED ON INDIVIDUAL PACKETS")
    print("*********************************************************")
    print(f"Identified Application Categories:")
    for app_category, count in application_categories.items():
        print(f"{app_category}: {count}")

    print("\nPORTS USED BY TRAFFIC IN THE 'Other' CATEGORY:")
    print(other_ports)
    protocol_counts, traffic_metrics = basic_dpi(captured_packets)
    print("Protocol Counts:")
    print(protocol_counts)
    print("*********************************************************")
    print("\n\n TRAFFIC METRICS:")
    print("*********************************************************")
    for metric, value in traffic_metrics.items():
        print(f"{metric}: {value}")