
import pytest

from network_monitor.traffic_rules import detect_packet_bursts


def test_detects_packets_within_time_window():
    packets = [
        (1.0, "192.168.1.10"),
        (2.0, "192.168.1.10"),
        (3.0, "192.168.1.10"),
        (20.0, "192.168.1.10"),
        (21.0, "192.168.1.10"),
    ]

    alerts = detect_packet_bursts(
        packets,
        window_seconds=5,
        threshold=3,
    )

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "192.168.1.10"
    assert alerts[0]["packet_count"] == 3
    assert alerts[0]["window_end"] == 3.0
    assert alerts[0]["type"] == "PACKET_BURST"


def test_does_not_alert_for_spread_out_packets():
    packets = [
        (1.0, "192.168.1.10"),
        (10.0, "192.168.1.10"),
        (20.0, "192.168.1.10"),
    ]

    alerts = detect_packet_bursts(
        packets,
        window_seconds=5,
        threshold=3,
    )

    assert alerts == []


def test_each_source_is_evaluated_separately():
    packets = [
        (1.0, "192.168.1.10"),
        (2.0, "192.168.1.10"),
        (3.0, "192.168.1.10"),
        (1.0, "192.168.1.20"),
        (2.0, "192.168.1.20"),
    ]

    alerts = detect_packet_bursts(
        packets,
        window_seconds=5,
        threshold=3,
    )

    assert [alert["source_ip"] for alert in alerts] == ["192.168.1.10"]


def test_invalid_window_or_threshold_is_rejected():
    with pytest.raises(ValueError):
        detect_packet_bursts([], window_seconds=0)

    with pytest.raises(ValueError):
        detect_packet_bursts([], threshold=0)
