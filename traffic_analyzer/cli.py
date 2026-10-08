"""Command line entry point."""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence

from .analyzer import Analyzer
from .report import format_bytes, generate_csv, generate_html


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="traffic-analyzer",
        description="Analyse a classic pcap file and generate an HTML/CSV report.",
    )
    parser.add_argument("pcap", help="path to a classic .pcap file")
    parser.add_argument(
        "-o",
        "--output",
        default="report.html",
        help="HTML report output path (default: report.html)",
    )
    parser.add_argument(
        "--csv",
        default=None,
        help="optional CSV summary output path",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=200,
        help="number of packets shown in the HTML preview (default: 200)",
    )
    parser.add_argument(
        "--port-scan-threshold",
        type=int,
        default=20,
        help="distinct destination ports needed to trigger a port-scan alert",
    )
    parser.add_argument(
        "--icmp-flood-threshold",
        type=int,
        default=50,
        help="ICMP packets from one source needed to trigger an alert",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    analyzer = Analyzer(
        port_scan_threshold=args.port_scan_threshold,
        icmp_flood_threshold=args.icmp_flood_threshold,
        keep_packets=args.max_packets,
    )

    try:
        result = analyzer.analyze_file(args.pcap)
    except FileNotFoundError:
        print("找不到文件：{}".format(args.pcap), file=sys.stderr)
        return 2
    except ValueError as error:
        print("解析失败：{}".format(error), file=sys.stderr)
        return 2

    generate_html(result, args.output, max_packets=args.max_packets)
    if args.csv:
        generate_csv(result, args.csv)

    print("解析完成")
    print("  数据包：{}".format(result.total_packets))
    print("  流量：{}".format(format_bytes(result.total_bytes)))
    print("  HTML 报告：{}".format(args.output))
    if args.csv:
        print("  CSV 摘要：{}".format(args.csv))
    if result.alerts:
        print("  告警：")
        for alert in result.alerts:
            print("    [{}] {} - {}".format(alert.severity, alert.kind, alert.message))
    else:
        print("  告警：未发现明显异常")
    return 0
