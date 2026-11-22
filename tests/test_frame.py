from datetime import UTC, datetime, timedelta, timezone

import pytest

from dc09_receiver.crc import crc16
from dc09_receiver.frame import (
    DecryptionError,
    FrameError,
    build_ack,
    build_duh,
    build_message,
    build_nak,
    parse_frame,
    parse_key,
)


def wrap(body: str) -> bytes:
    raw = body.encode()
    return b"\n" + f"{crc16(raw):04X}{len(raw):04X}".encode() + raw + b"\r"


def test_parse_contact_id():
    f = parse_frame(wrap('"ADM-CID"0007R1L2#1234[#1234|1130 01 015]'))
    assert f.msg_id == "ADM-CID"
    assert f.sequence == "0007"
    assert (f.receiver, f.line, f.account) == ("1", "2", "1234")
    assert f.data == "1130 01 015"
    assert f.crc_ok and f.length_ok and not f.encrypted


def test_parse_sia_with_timestamp_and_xdata():
    f = parse_frame(wrap('"SIA-DCS"0002L0#1234[#1234|Nri1/BA01][X077W12.3456][Vsite-a]_14:12:04,09-25-2026'))
    assert f.data == "Nri1/BA01"
    assert f.extended == ("X077W12.3456", "Vsite-a")
    assert f.timestamp == datetime(2026, 9, 25, 14, 12, 4, tzinfo=UTC)


def test_parse_null():
    f = parse_frame(wrap('"NULL"0000R0L0#1234[]'))
    assert f.msg_id == "NULL" and f.data == ""


def test_long_numeric_account_is_not_confused_with_payload():
    f = parse_frame(wrap('"ADM-CID"0001L0#9876543210AB[#9876543210AB|3401 02 007]'))
    assert f.account == "9876543210AB"
    assert f.data == "3401 02 007"


def test_bad_crc_is_reported_not_raised():
    good = wrap('"ADM-CID"0001L0#1234[#1234|1130 01 015]')
    bad = good[:1] + b"0000" + good[5:]
    f = parse_frame(bad)
    assert not f.crc_ok and f.length_ok and not f.valid


def test_wrong_length_detected():
    raw = b'"ADM-CID"0001L0#1234[#1234|1130 01 015]'
    msg = b"\n" + f"{crc16(raw):04X}0001".encode() + raw + b"\r"
    assert parse_frame(msg).length_ok is False


@pytest.mark.parametrize("junk", [b"", b"\r", b"hello world\r", b"\n00000000garbage\r"])
def test_garbage_raises(junk):
    with pytest.raises(FrameError):
        parse_frame(junk)


def test_ack_echoes_sequence_and_routing():
    f = parse_frame(wrap('"ADM-CID"0042R5L7#1234[#1234|1130 01 015]'))
    ack = build_ack(f)
    assert ack.startswith(b"\n") and ack.endswith(b"\r")
    a = parse_frame(ack)
    assert (a.msg_id, a.sequence, a.receiver, a.line, a.account) == ("ACK", "0042", "5", "7", "1234")
    assert a.crc_ok and a.length_ok


def test_ack_overrides():
    f = parse_frame(wrap('"ADM-CID"0001L0#1234[#1234|1130 01 015]'))
    a = parse_frame(build_ack(f, receiver="9", line="3"))
    assert (a.receiver, a.line) == ("9", "3")


def test_nak_and_duh():
    nak = parse_frame(build_nak(receiver="1"))
    assert nak.msg_id == "NAK" and nak.timestamp is not None
    f = parse_frame(wrap('"ADM-CID"0003L0#1234[#1234|1130 01 015]'))
    duh = parse_frame(build_duh(f))
    assert duh.msg_id == "DUH" and duh.sequence == "0003"


def test_build_message_roundtrip():
    msg = build_message("ADM-CID", "1234", "1130 01 015", sequence=12, receiver="1")
    f = parse_frame(msg)
    assert f.valid and f.sequence == "0012" and f.data == "1130 01 015" and f.timestamp


def test_encrypted_roundtrip(key):
    when = datetime.now(UTC).replace(microsecond=0)
    msg = build_message("SIA-DCS", "ABCD", "Nri1/BA01", key=key, timestamp=when)
    assert b'"*SIA-DCS"' in msg
    assert b"BA01" not in msg  # payload really is encrypted
    f = parse_frame(msg, key_lookup=lambda acct: key if acct == "ABCD" else None)
    assert f.encrypted and f.valid
    assert f.data == "Nri1/BA01"
    assert f.timestamp == when


def test_encrypted_ack_roundtrip(key):
    f = parse_frame(build_message("ADM-CID", "ABCD", "1130 01 001", key=key), key_lookup=lambda _a: key)
    ack = build_ack(f, key=key)
    assert b'"*ACK"' in ack
    a = parse_frame(ack, key_lookup=lambda _a: key)
    assert a.msg_id == "ACK" and a.encrypted and a.timestamp is not None


def test_encrypted_without_key(key):
    msg = build_message("ADM-CID", "ABCD", "1130 01 001", key=key)
    with pytest.raises(DecryptionError) as exc:
        parse_frame(msg, key_lookup=lambda _a: None)
    assert exc.value.frame is not None and exc.value.frame.account == "ABCD"


def test_encrypted_wrong_key(key):
    msg = build_message("ADM-CID", "ABCD", "1130 01 001", key=key)
    other = bytes(16)
    with pytest.raises(DecryptionError):
        parse_frame(msg, key_lookup=lambda _a: other)


@pytest.mark.parametrize(
    ("value", "length"),
    [
        ("00" * 16, 16),
        ("00" * 24, 24),
        ("hex:" + "00" * 32, 32),
        ("A" * 16, 16),
        ("ascii:" + "B" * 32, 32),
        ("B" * 32, 16),  # bare 32 hex chars are read as hex
    ],
)
def test_parse_key(value, length):
    assert len(parse_key(value)) == length


def test_parse_key_rejects_bad_length():
    with pytest.raises(ValueError):
        parse_key("short")


def test_timestamp_is_utc():
    when = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=-5)))
    f = parse_frame(build_message("NULL", "1234", "", timestamp=when))
    assert f.timestamp == datetime(2026, 1, 2, 8, 4, 5, tzinfo=UTC)
