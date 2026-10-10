
import argparse
import json
import sys

from network_monitor.alerts import detect_high_packet_sources
from network_monitor.analyzer import analyze_pcap


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a PCAP file and summarize network traffic."
    )
    parser.add_argument(
        "pcap_file",
        help="Path to the PCAP or PCAPNG file to analyze",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=100,
        help="Alert when a source IP has at least this many packets (default: 100)",
    )
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")

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
    results.pop("source_packet_counts", None)

    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
