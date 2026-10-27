
import subprocess
import sys
from pathlib import Path

from network_monitor.analyzer import analyze_pcap
from network_monitor.traffic_rules import detect_packet_bursts


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_generated_demo_produces_expected_burst_alert(tmp_path):
    # Generate the demo in a temporary copy of the expected output location.
    demo_path = tmp_path / "demo.pcap"

    script = PROJECT_ROOT / "scripts" / "generate_demo_pcap.py"

    # Run the generator in an isolated temporary project structure.
    isolated_scripts = tmp_path / "scripts"
    isolated_samples = tmp_path / "samples"
    isolated_scripts.mkdir()
    isolated_samples.mkdir()

    isolated_script = isolated_scripts / "generate_demo_pcap.py"
    isolated_script.write_text(
        script.read_text(encoding="utf-8").replace(
            'project_root = Path(__file__).resolve().parents[1]',
            f'project_root = Path(r"{tmp_path}")',
        ),
        encoding="utf-8",
    )

    subprocess.run(
        [sys.executable, str(isolated_script)],
        check=True,
        capture_output=True,
        text=True,
    )

    assert (isolated_samples / "demo.pcap").is_file()
    assert demo_path == tmp_path / "demo.pcap"

    result = analyze_pcap(isolated_samples / "demo.pcap")

    alerts = detect_packet_bursts(
        result["timestamped_sources"],
        window_seconds=5,
        threshold=5,
    )

    assert result["total_packets"] == 7
    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "192.0.2.10"
    assert alerts[0]["packet_count"] == 5
