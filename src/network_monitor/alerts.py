
from collections.abc import Mapping


def detect_high_packet_sources(
    source_counts: Mapping[str, int],
    threshold: int = 100,
) -> list[dict]:
    """Flag source IPs whose packet count meets or exceeds a threshold."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    alerts = []

    for source_ip, packet_count in sorted(source_counts.items()):
        if packet_count >= threshold:
            alerts.append(
                {
                    "type": "HIGH_PACKET_COUNT",
                    "source_ip": source_ip,
                    "packet_count": packet_count,
                    "threshold": threshold,
                    "severity": "medium",
                    "reason": (
                        f"Source sent {packet_count} packets, "
                        f"meeting or exceeding the threshold of {threshold}."
                    ),
                }
            )

    return alerts
