# Network Security Monitor

An offline network traffic analysis tool built with Python and Scapy. It analyzes PCAP files, summarizes protocol and IP activity, and generates explainable alerts based on configurable packet-count thresholds.

## Features

- Offline PCAP and PCAPNG analysis
- TCP, UDP, ICMP, and other packet classification
- IPv4 and IPv6 source/destination statistics
- Top source IP reporting
- Configurable high-packet-count alerts
- JSON output for further analysis
- Automated tests using synthetic packet captures

## Requirements

- Python 3.11 or newer
- Dependencies listed in `requirements.txt`

## Installation

Clone the repository and enter its directory:

```bash
git clone https://github.com/aminh-cs/network-security-monitor.git
cd network-security-monitor
```

Create and activate a virtual environment.

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the project and its dependencies:

```powershell
python -m pip install -r requirements.txt
python -m pip install -e . --no-build-isolation
```

## Usage

Show available options:

```powershell
python -m network_monitor --help
```

Analyze a capture:

```powershell
python -m network_monitor samples\demo.pcap
```

Set the alert threshold to 100 packets per source IP:

```powershell
python -m network_monitor samples\demo.pcap --threshold 100
```

The tool prints a JSON report containing packet totals, protocol counts, IP statistics, top source IPs, and generated alerts.

## Alerts

The current `HIGH_PACKET_COUNT` rule flags a source IP when its total packet count in the capture meets or exceeds the configured threshold.

This is a basic heuristic, not proof of malicious activity. Legitimate high-volume hosts may trigger alerts. The current rule does not calculate packets per second or normalize counts by capture duration.

## Testing

Run the automated test suite:

```powershell
python -m pytest -v
```

The tests use synthetic packet captures and temporary files. They do not require live packet capture or access to a production network.

## Ethical and privacy considerations

- Analyze only packet captures you own or are authorized to inspect.
- Packet captures may contain sensitive addresses, metadata, or payloads.
- Do not commit confidential PCAP files or real organizational traffic.
- This tool reports heuristic indicators; it does not prove that a host is compromised.

## Current limitations

- Alerts are based on total packet counts, not time-windowed traffic rates.
- No live capture, automatic blocking, or active scanning.
- Alert thresholds require manual configuration.
- No persistent database or dashboard.

## Planned improvements

- GitHub Actions continuous integration
- Additional explainable detection rules
- Synthetic example data and reproducible demonstrations
- Improved validation and test coverage

## License

No license has been added yet. Reuse and redistribution are subject to the repository owner's permission until a license is selected.