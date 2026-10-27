
from collections import Counter
from pathlib import Path

from scapy.all import IP, IPv6, ICMP, TCP, UDP, rdpcap


def analyze_pcap(file_path: str | Path) -> dict:
    """Analyze a PCAP file and return basic network statistics."""
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    packets = rdpcap(str(path))

    protocol_counts = Counter()
    source_ips = Counter()
    destination_ips = Counter()
    timestamped_sources = []

    for packet in packets:
        if TCP in packet:
            protocol_counts["TCP"] += 1
        elif UDP in packet:
            protocol_counts["UDP"] += 1
        elif ICMP in packet:
            protocol_counts["ICMP"] += 1
        else:
            protocol_counts["OTHER"] += 1

        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
        elif IPv6 in packet:
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst
        else:
            continue

        source_ips[source_ip] += 1
        destination_ips[destination_ip] += 1
        timestamped_sources.append((float(packet.time), source_ip))

    return {
        "file": path.name,
        "total_packets": len(packets),
        "protocol_counts": dict(sorted(protocol_counts.items())),
        "unique_source_ips": len(source_ips),
        "unique_destination_ips": len(destination_ips),
        "top_source_ips": source_ips.most_common(5),
        "source_packet_counts": dict(sorted(source_ips.items())),
        "timestamped_sources": timestamped_sources,
    }
