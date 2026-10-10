
import pytest

from network_monitor.alerts import detect_high_packet_sources


def test_alerts_source_at_or_above_threshold():
    counts = {
        "192.168.1.10": 99,
        "192.168.1.20": 100,
        "192.168.1.30": 150,
    }

    alerts = detect_high_packet_sources(counts, threshold=100)

    assert [alert["source_ip"] for alert in alerts] == [
        "192.168.1.20",
        "192.168.1.30",
    ]
    assert alerts[0]["type"] == "HIGH_PACKET_COUNT"
    assert alerts[0]["severity"] == "medium"
    assert alerts[0]["threshold"] == 100


def test_no_alert_when_all_counts_are_below_threshold():
    alerts = detect_high_packet_sources(
        {"192.168.1.10": 20},
        threshold=100,
    )

    assert alerts == []


def test_threshold_must_be_positive():
    with pytest.raises(ValueError, match="threshold must be at least 1"):
        detect_high_packet_sources({"192.168.1.10": 10}, threshold=0)
