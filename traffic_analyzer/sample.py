"""Generate a small synthetic pcap file for demos and tests.

The generated capture contains normal HTTP-like TCP traffic, DNS-like UDP
traffic, a few ICMP echo packets and a small TCP SYN port scan.  No external
data or third-party library is required.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _mac(value: str) -> bytes:
    return bytes(int(part, 16) for part in value.split(":"))


def _ipv4(src: str, dst: str, protocol: int, payload: bytes) -> bytes:
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0x1234,
        0,
        64,
        protocol,
        0,
        bytes(int(part) for part in src.split(".")),
        bytes(int(part) for part in dst.split(".")),
    )
    checksum = _checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header + payload


def _tcp(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    flags: int,
    sequence: int = 0,
    acknowledgement: int = 0,
    payload: bytes = b"",
) -> bytes:
    offset_flags = (5 << 12) | flags
    header = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        sequence,
        acknowledgement,
        offset_flags,
        65535,
        0,
        0,
    )
    pseudo = (
        bytes(int(part) for part in src_ip.split("."))
        + bytes(int(part) for part in dst_ip.split("."))
        + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    )
    checksum = _checksum(pseudo + header + payload)
    header = header[:16] + struct.pack("!H", checksum) + header[18:]
    return _ipv4(src_ip, dst_ip, 6, header + payload)


def _udp(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes = b"",
) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = (
        bytes(int(part) for part in src_ip.split("."))
        + bytes(int(part) for part in dst_ip.split("."))
        + struct.pack("!BBH", 0, 17, length)
    )
    checksum = _checksum(pseudo + header + payload)
    header = header[:6] + struct.pack("!H", checksum)
    return _ipv4(src_ip, dst_ip, 17, header + payload)


def _icmp_echo(src_ip: str, dst_ip: str, identifier: int, sequence: int) -> bytes:
    payload = b"network-traffic-analyzer-demo"
    header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    checksum = _checksum(header + payload)
    header = struct.pack("!BBHHH", 8, 0, checksum, identifier, sequence)
    return _ipv4(src_ip, dst_ip, 1, header + payload)


def _ethernet(payload: bytes) -> bytes:
    return (
        _mac("02:00:00:00:00:01")
        + _mac("02:00:00:00:00:02")
        + struct.pack("!H", 0x0800)
        + payload
    )


def _pcap_record(timestamp: float, frame: bytes) -> bytes:
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1_000_000)
    return struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)) + frame


def build_sample_pcap(output_path: str) -> str:
    """Write a synthetic pcap file and return its path."""
    packets: List[Tuple[float, bytes]] = []
    timestamp = 1_700_000_000.0

    def add(frame: bytes, step: float = 0.01) -> None:
        nonlocal timestamp
        packets.append((timestamp, _ethernet(frame)))
        timestamp += step

    # Normal HTTP-like TCP handshake and data.
    for sequence in range(6):
        add(
            _tcp(
                "192.168.1.10",
                "10.0.0.5",
                41000 + sequence,
                80,
                0x02 if sequence == 0 else 0x10,
                sequence=1000 + sequence * 100,
                acknowledgement=2000 + sequence * 100,
            )
        )

    # DNS-like UDP traffic.
    for index in range(5):
        add(
            _udp(
                "192.168.1.10",
                "8.8.8.8",
                53000 + index,
                53,
                b"\x12\x34\x01\x00" + bytes([0, index]),
            )
        )
        add(
            _udp(
                "8.8.8.8",
                "192.168.1.10",
                53,
                53000 + index,
                b"\x12\x34\x81\x80" + bytes([0, index]),
            )
        )

    # A few ICMP echo packets.
    for sequence in range(3):
        add(_icmp_echo("192.168.1.10", "10.0.0.5", 1, sequence), step=0.05)

    # A small TCP SYN scan from 10.0.0.99 to 192.168.1.10:1..30.
    for port in range(1, 31):
        add(
            _tcp(
                "10.0.0.99",
                "192.168.1.10",
                55000 + port,
                port,
                0x02,
                sequence=port,
            ),
            step=0.005,
        )

    header = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        1,
    )
    output = Path(output_path)
    output.write_bytes(header + b"".join(_pcap_record(ts, frame) for ts, frame in packets))
    return str(output)


if __name__ == "__main__":
    print(build_sample_pcap("sample.pcap"))
