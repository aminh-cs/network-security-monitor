
import json

from scapy.all import Ether, IP, TCP, wrpcap

from network_monitor.cli import main


def test_cli_reports_high_packet_source(tmp_path, monkeypatch, capsys):
    packets = [
        Ether() / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=12345 + index, dport=443)
        for index in range(3)
    ]
    pcap_path = tmp_path / "traffic.pcap"
    wrpcap(str(pcap_path), packets)

    monkeypatch.setattr(
        "sys.argv",
        ["network-monitor", str(pcap_path), "--threshold", "3"],
    )

    exit_code = main()
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["total_packets"] == 3
    assert len(output["alerts"]) == 1
    assert output["alerts"][0]["source_ip"] == "192.168.1.10"
    assert output["alerts"][0]["packet_count"] == 3
