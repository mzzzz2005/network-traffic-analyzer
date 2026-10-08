"""Traffic statistics and rule-based anomaly detection."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import DefaultDict, Dict, List, Optional, Set, Tuple

from .packets import Packet, parse_packet
from .pcap import read_pcap


@dataclass
class Alert:
    kind: str
    severity: str
    src: str
    message: str
    evidence: str


@dataclass
class AnalysisResult:
    pcap_path: str
    total_packets: int = 0
    total_bytes: int = 0
    first_timestamp: Optional[float] = None
    last_timestamp: Optional[float] = None
    protocols: Counter = field(default_factory=Counter)
    src_ips: Counter = field(default_factory=Counter)
    dst_ips: Counter = field(default_factory=Counter)
    dst_ports: Counter = field(default_factory=Counter)
    tcp_flags: Counter = field(default_factory=Counter)
    icmp_types: Counter = field(default_factory=Counter)
    alerts: List[Alert] = field(default_factory=list)
    packets: List[Packet] = field(default_factory=list)

    @property
    def duration(self) -> float:
        if self.first_timestamp is None or self.last_timestamp is None:
            return 0.0
        return max(0.0, self.last_timestamp - self.first_timestamp)


class Analyzer:
    """Analyse a pcap file and return an :class:`AnalysisResult`."""

    def __init__(
        self,
        port_scan_threshold: int = 20,
        icmp_flood_threshold: int = 50,
        keep_packets: int = 200,
    ) -> None:
        self.port_scan_threshold = port_scan_threshold
        self.icmp_flood_threshold = icmp_flood_threshold
        self.keep_packets = keep_packets

    def analyze_file(self, path: str) -> AnalysisResult:
        result = AnalysisResult(pcap_path=path)
        syn_ports: DefaultDict[str, Set[int]] = defaultdict(set)
        syn_counts: Counter = Counter()
        icmp_counts: Counter = Counter()

        for raw_packet in read_pcap(path):
            packet = parse_packet(raw_packet.timestamp, raw_packet.data)
            if packet is None:
                continue

            self._update(result, packet)

            if packet.protocol == "TCP":
                syn_only = bool(packet.tcp_flags & 0x02) and not bool(
                    packet.tcp_flags & 0x10
                )
                if syn_only and packet.dst_port is not None:
                    syn_ports[packet.src_ip].add(packet.dst_port)
                    syn_counts[packet.src_ip] += 1
            elif packet.protocol == "ICMP":
                icmp_counts[packet.src_ip] += 1

            if len(result.packets) < self.keep_packets:
                result.packets.append(packet)

        for src_ip, ports in syn_ports.items():
            if len(ports) >= self.port_scan_threshold:
                result.alerts.append(
                    Alert(
                        kind="端口扫描",
                        severity="high",
                        src=src_ip,
                        message="{} 向 {} 个不同端口发起 TCP SYN".format(
                            src_ip, len(ports)
                        ),
                        evidence="SYN 包 {} 个，目标端口示例：{}".format(
                            syn_counts[src_ip],
                            ", ".join(str(port) for port in sorted(ports)[:8]),
                        ),
                    )
                )

        for src_ip, count in icmp_counts.items():
            if count >= self.icmp_flood_threshold:
                result.alerts.append(
                    Alert(
                        kind="ICMP 流量异常",
                        severity="medium",
                        src=src_ip,
                        message="{} 发送了 {} 个 ICMP 包".format(src_ip, count),
                        evidence="可能是 ICMP Flood、Ping Sweep 或主机发现行为",
                    )
                )

        return result

    def _update(self, result: AnalysisResult, packet: Packet) -> None:
        result.total_packets += 1
        result.total_bytes += packet.length

        if result.first_timestamp is None or packet.timestamp < result.first_timestamp:
            result.first_timestamp = packet.timestamp
        if result.last_timestamp is None or packet.timestamp > result.last_timestamp:
            result.last_timestamp = packet.timestamp

        result.protocols[packet.protocol] += 1
        result.src_ips[packet.src_ip] += 1
        result.dst_ips[packet.dst_ip] += 1
        if packet.dst_port is not None:
            result.dst_ports[packet.dst_port] += 1
        if packet.protocol == "TCP":
            result.tcp_flags[packet.tcp_flags] += 1
        if packet.protocol == "ICMP" and packet.icmp_type is not None:
            result.icmp_types[packet.icmp_type] += 1
