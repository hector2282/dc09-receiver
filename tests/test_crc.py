from dc09_receiver.crc import crc16


def test_crc16_arc_check_value():
    # Standard check value for CRC-16/ARC.
    assert crc16(b"123456789") == 0xBB3D


def test_crc16_empty():
    assert crc16(b"") == 0
