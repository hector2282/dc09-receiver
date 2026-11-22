"""CRC used by ANSI/SIA DC-09 (CRC-16/ARC, polynomial 0x8005 reflected)."""

from __future__ import annotations

__all__ = ["crc16"]


def _table() -> list[int]:
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
        table.append(crc)
    return table


_TABLE = _table()


def crc16(data: bytes) -> int:
    """Return the CRC-16/ARC of *data* (init 0x0000, no final XOR)."""
    crc = 0
    for b in data:
        crc = (crc >> 8) ^ _TABLE[(crc ^ b) & 0xFF]
    return crc
