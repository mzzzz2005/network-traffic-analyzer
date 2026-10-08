"""Create a synthetic pcap file for the demo.

Usage:
    python examples/make_sample_pcap.py sample.pcap
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from traffic_analyzer.sample import build_sample_pcap


def main() -> int:
    output = sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"
    print(build_sample_pcap(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
