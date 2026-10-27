
import argparse
import json
import sys

from network_monitor.alerts import detect_high_packet_sources
from network_monitor.analyzer import analyze_pcap
from network_monitor.traffic_rules import detect_packet_bursts


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a PCAP file and detect unusual packet activity."
    )
    parser.add_argument(
        "pcap_file",
        help="Path to the PCAP or PCAPNG file to analyze",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=100,
        help="Whole-capture packet-count alert threshold (default: 100)",
    )
    parser.add_argument(
        "--window-seconds",
        type=float,
        default=10.0,
        help="Rolling time-window duration in seconds (default: 10)",
    )
    parser.add_argument(
        "--burst-threshold",
        type=int,
        default=20,
        help="Packets from one source needed for a burst alert (default: 20)",
    )
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if args.window_seconds <= 0:
        parser.error("--window-seconds must be greater than 0")
    if args.burst_threshold < 1:
        parser.error("--burst-threshold must be at least 1")

    try:
        results = analyze_pcap(args.pcap_file)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"Error reading capture: {exc}", file=sys.stderr)
        return 1

    results["alerts"] = detect_high_packet_sources(
        results["source_packet_counts"],
        threshold=args.threshold,
    )
    results["burst_alerts"] = detect_packet_bursts(
        results["timestamped_sources"],
        window_seconds=args.window_seconds,
        threshold=args.burst_threshold,
    )

    # Internal fields are used for detection but omitted from the report.
    results.pop("source_packet_counts", None)
    results.pop("timestamped_sources", None)

    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
