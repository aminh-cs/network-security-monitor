
from scapy.all import IP, TCP, UDP, Ether, wrpcap

from network_monitor.analyzer import analyze_pcap

from scapy.all import IP, IPv6, TCP, UDP, Ether, Raw, wrpcap

def test_analyze_pcap_counts_protocols_and_ips(tmp_path):
    packets = [
        Ether() / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=12345, dport=443),
        Ether() / IP(src="192.168.1.10", dst="192.168.1.30")
        / UDP(sport=53000, dport=53),
        Ether() / IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=443, dport=12345),
    ]

    pcap_path = tmp_path / "synthetic.pcap"
    wrpcap(str(pcap_path), packets)

    result = analyze_pcap(pcap_path)

    assert result["total_packets"] == 3
    assert result["protocol_counts"] == {"TCP": 2, "UDP": 1}
    assert result["unique_source_ips"] == 2
    assert result["unique_destination_ips"] == 3
    assert result["top_source_ips"][0] == ("192.168.1.10", 2)


def test_analyze_pcap_missing_file_raises_error(tmp_path):
    missing_path = tmp_path / "missing.pcap"

    try:
        analyze_pcap(missing_path)
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Expected FileNotFoundError")

def test_analyze_empty_pcap(tmp_path):
    pcap_path = tmp_path / "empty.pcap"
    wrpcap(str(pcap_path), [])

    result = analyze_pcap(pcap_path)

    assert result["total_packets"] == 0
    assert result["protocol_counts"] == {}
    assert result["unique_source_ips"] == 0
    assert result["unique_destination_ips"] == 0
    assert result["top_source_ips"] == []


def test_analyze_ipv6_packet(tmp_path):
    packets = [
        Ether()
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=12345, dport=443)
    ]

    pcap_path = tmp_path / "ipv6.pcap"
    wrpcap(str(pcap_path), packets)

    result = analyze_pcap(pcap_path)

    assert result["total_packets"] == 1
    assert result["protocol_counts"] == {"TCP": 1}
    assert result["unique_source_ips"] == 1
    assert result["unique_destination_ips"] == 1
    assert result["top_source_ips"] == [("2001:db8::1", 1)]


def test_analyze_packet_without_ip(tmp_path):
    packets = [Ether() / Raw(load=b"sample ethernet payload")]

    pcap_path = tmp_path / "non_ip.pcap"
    wrpcap(str(pcap_path), packets)

    result = analyze_pcap(pcap_path)

    assert result["total_packets"] == 1
    assert result["protocol_counts"] == {"OTHER": 1}
    assert result["unique_source_ips"] == 0
    assert result["unique_destination_ips"] == 0
