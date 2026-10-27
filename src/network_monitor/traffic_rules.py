
from collections import defaultdict
from collections.abc import Iterable, Mapping


def detect_packet_bursts(
    timestamped_sources: Iterable[tuple[float, str]],
    *,
    window_seconds: float = 10.0,
    threshold: int = 20,
) -> list[dict]:
    """Flag source IPs meeting the packet threshold in a time window.

    Each input item is a (timestamp, source_ip) pair.
    Windows are rolling: packets are counted within the preceding
    window_seconds, including packets exactly on the window boundary.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than 0")
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    packets_by_source = defaultdict(list)

    for timestamp, source_ip in timestamped_sources:
        packets_by_source[source_ip].append(float(timestamp))

    alerts = []

    for source_ip, timestamps in sorted(packets_by_source.items()):
        timestamps.sort()
        left = 0
        peak_count = 0
        peak_end = None

        for right, end_time in enumerate(timestamps):
            while end_time - timestamps[left] > window_seconds:
                left += 1

            count = right - left + 1
            if count > peak_count:
                peak_count = count
                peak_end = end_time

        if peak_count >= threshold:
            alerts.append(
                {
                    "type": "PACKET_BURST",
                    "source_ip": source_ip,
                    "packet_count": peak_count,
                    "window_seconds": window_seconds,
                    "threshold": threshold,
                    "window_end": peak_end,
                    "severity": "medium",
                    "reason": (
                        f"Source sent {peak_count} packets within "
                        f"{window_seconds:g} seconds, meeting or exceeding "
                        f"the threshold of {threshold}."
                    ),
                }
            )

    return alerts
