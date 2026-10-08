"""Minimal reader for classic libpcap files.

Only the classic pcap format is supported.  pcapng is intentionally out of
scope because the goal of this project is a small, readable and dependency-free
network traffic analyser for learning and portfolio use.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Tuple


class PcapError(ValueError):
    """Raised when a pcap file cannot be parsed."""


@dataclass(frozen=True)
class PcapPacket:
    timestamp: float
    data: bytes
    original_length: int


# magic bytes -> (endian prefix, nanosecond timestamps)
_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}


def _u32(endian: str, data: bytes) -> int:
    return struct.unpack(endian + "I", data)[0]


def read_pcap(path: str) -> Iterator[PcapPacket]:
    """Yield packets from a classic pcap file."""
    pcap_path = Path(path)
    with pcap_path.open("rb") as handle:
        global_header = handle.read(24)
        if len(global_header) < 24:
            raise PcapError("pcap global header is incomplete")

        magic = global_header[:4]
        if magic not in _PCAP_MAGIC:
            raise PcapError(
                "unsupported pcap magic bytes; only classic pcap is supported "
                "(pcapng is not supported)"
            )
        endian, nanosecond = _PCAP_MAGIC[magic]
        link_type = _u32(endian, global_header[20:24])
        if link_type != 1:
            raise PcapError(
                "unsupported link type {}; only Ethernet (1) is supported".format(
                    link_type
                )
            )

        divisor = 1_000_000_000 if nanosecond else 1_000_000
        while True:
            packet_header = handle.read(16)
            if not packet_header:
                break
            if len(packet_header) < 16:
                break

            ts_sec, ts_frac, included_len, original_len = struct.unpack(
                endian + "IIII", packet_header
            )
            packet_data = handle.read(included_len)
            if len(packet_data) < included_len:
                break
            yield PcapPacket(
                timestamp=ts_sec + (ts_frac / divisor),
                data=packet_data,
                original_length=original_len,
            )
