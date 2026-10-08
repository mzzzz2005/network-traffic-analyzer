import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from traffic_analyzer.analyzer import Analyzer
from traffic_analyzer.packets import parse_packet, tcp_flag_names
from traffic_analyzer.sample import build_sample_pcap


def _minimal_udp_frame() -> bytes:
    ethernet = (
        b"\x02\x00\x00\x00\x00\x01"
        + b"\x02\x00\x00\x00\x00\x02"
        + struct.pack("!H", 0x0800)
    )
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        28,
        1,
        0,
        64,
        17,
        0,
        bytes([1, 1, 1, 1]),
        bytes([2, 2, 2, 2]),
    )
    udp_header = struct.pack("!HHHH", 12345, 53, 8, 0)
    return ethernet + ip_header + udp_header


class PacketParsingTests(unittest.TestCase):
    def test_parse_udp_packet(self) -> None:
        packet = parse_packet(123.0, _minimal_udp_frame())
        self.assertIsNotNone(packet)
        assert packet is not None
        self.assertEqual(packet.protocol, "UDP")
        self.assertEqual(packet.src_ip, "1.1.1.1")
        self.assertEqual(packet.dst_ip, "2.2.2.2")
        self.assertEqual(packet.src_port, 12345)
        self.assertEqual(packet.dst_port, 53)

    def test_tcp_flag_names(self) -> None:
        self.assertEqual(tcp_flag_names(0x02), "SYN")
        self.assertEqual(tcp_flag_names(0x12), "SYN,ACK")
        self.assertEqual(tcp_flag_names(0x00), "NONE")


class AnalyzerTests(unittest.TestCase):
    def test_sample_pcap_triggers_port_scan_alert(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pcap_path = os.path.join(temp_dir, "sample.pcap")
            build_sample_pcap(pcap_path)
            result = Analyzer(port_scan_threshold=20).analyze_file(pcap_path)
            self.assertGreater(result.total_packets, 0)
            self.assertTrue(any(alert.kind == "端口扫描" for alert in result.alerts))


if __name__ == "__main__":
    unittest.main()
