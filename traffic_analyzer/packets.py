"""Ethernet / IPv4 / TCP / UDP / ICMP packet parsing without third-party libraries."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional


@dataclass
class Packet:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: int = 0
    icmp_type: Optional[int] = None
    length: int = 0
    payload: bytes = b""

    @property
    def src_endpoint(self) -> str:
        if self.src_port is None:
            return self.src_ip
        return "{}:{}".format(self.src_ip, self.src_port)

    @property
    def dst_endpoint(self) -> str:
        if self.dst_port is None:
            return self.dst_ip
        return "{}:{}".format(self.dst_ip, self.dst_port)


def _ipv4_to_str(raw: bytes) -> str:
    return ".".join(str(part) for part in raw)


def parse_packet(timestamp: float, data: bytes) -> Optional[Packet]:
    """Parse one Ethernet frame into a Packet.

    Returns None for non-IPv4 frames, malformed frames, or unsupported link
    layer payloads.  This keeps the main analyser free from noisy exceptions.
    """
    if len(data) < 14:
        return None

    ether_type = struct.unpack("!H", data[12:14])[0]
    offset = 14

    # Single 802.1Q VLAN tag.
    if ether_type == 0x8100:
        if len(data) < 18:
            return None
        ether_type = struct.unpack("!H", data[16:18])[0]
        offset = 18

    if ether_type != 0x0800:
        return None
    if len(data) < offset + 20:
        return None

    ip = data[offset:]
    version = ip[0] >> 4
    ihl = (ip[0] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(ip) < ihl:
        return None

    total_length = struct.unpack("!H", ip[2:4])[0]
    protocol_number = ip[9]
    src_ip = _ipv4_to_str(ip[12:16])
    dst_ip = _ipv4_to_str(ip[16:20])

    if total_length < ihl:
        return None
    payload = ip[ihl:total_length]

    if protocol_number == 6:  # TCP
        if len(payload) < 20:
            return None
        src_port, dst_port = struct.unpack("!HH", payload[0:4])
        data_offset = (payload[12] >> 4) * 4
        if data_offset < 20 or len(payload) < data_offset:
            return None
        flags = payload[13]
        return Packet(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="TCP",
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=flags,
            length=total_length,
            payload=payload[data_offset:],
        )

    if protocol_number == 17:  # UDP
        if len(payload) < 8:
            return None
        src_port, dst_port, udp_length = struct.unpack("!HHH", payload[0:6])
        if udp_length < 8:
            return None
        return Packet(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="UDP",
            src_port=src_port,
            dst_port=dst_port,
            length=total_length,
            payload=payload[8:udp_length],
        )

    if protocol_number == 1:  # ICMP
        if len(payload) < 4:
            return None
        return Packet(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="ICMP",
            icmp_type=payload[0],
            length=total_length,
            payload=payload[4:],
        )

    return Packet(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol="IP/{}".format(protocol_number),
        length=total_length,
        payload=payload,
    )


def tcp_flag_names(flags: int) -> str:
    """Return a readable TCP flags string, e.g. ``SYN,ACK``."""
    names = []
    for bit, name in (
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ):
        if flags & bit:
            names.append(name)
    return ",".join(names) if names else "NONE"
