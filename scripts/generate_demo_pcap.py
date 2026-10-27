
from pathlib import Path

from scapy.all import Ether, IP, TCP, wrpcap


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    output_path = project_root / "samples" / "demo.pcap"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    packets = []

    # Five synthetic TCP packets within a short time window.
    for index in range(5):
        packet = (
            Ether()
            / IP(src="192.0.2.10", dst="198.51.100.20")
            / TCP(sport=40000 + index, dport=443, flags="S")
        )
        packet.time = 1_700_000_000.0 + index * 0.5
        packets.append(packet)

    # Two more packets, deliberately outside the first burst window.
    for index in range(2):
        packet = (
            Ether()
            / IP(src="192.0.2.30", dst="198.51.100.20")
            / TCP(sport=41000 + index, dport=443, flags="S")
        )
        packet.time = 1_700_000_030.0 + index * 10.0
        packets.append(packet)

    wrpcap(str(output_path), packets)
    print(f"Created synthetic demo capture: {output_path}")
    print(f"Packets written: {len(packets)}")


if __name__ == "__main__":
    main()
