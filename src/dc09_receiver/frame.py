"""Parse and build ANSI/SIA DC-09 messages.

Wire format (ASCII)::

    <LF> CRC(4 hex) 0LLL(4 hex) "ID" seq Rrcvr Lpref #acct [data] [xdata] _timestamp <CR>

The CRC and the length cover everything from the opening quote of ``"ID"``
up to (not including) the trailing ``<CR>``.

For encrypted messages the ID starts with ``*`` and everything after the
opening ``[`` is AES-CBC (zero IV) ciphertext, hex encoded. The plaintext is::

    <pad> "|" <data> "]" [xdata...] "_" <timestamp>

where ``<pad>`` makes the plaintext a multiple of 16 bytes and never contains
``|``, ``[`` or ``]``.
"""

from __future__ import annotations

import re
import secrets
import string
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .crc import crc16

__all__ = [
    "DecryptionError",
    "Frame",
    "FrameError",
    "build_ack",
    "build_duh",
    "build_message",
    "build_nak",
    "format_timestamp",
    "parse_frame",
    "parse_key",
]

LF = 0x0A
CR = 0x0D
_TS_FORMAT = "%H:%M:%S,%m-%d-%Y"
_PAD_ALPHABET = string.ascii_letters + string.digits

KeyLookup = Callable[[str], "bytes | None"]


class FrameError(ValueError):
    """The bytes are not a DC-09 message."""


class DecryptionError(FrameError):
    """The message is encrypted and could not be decrypted."""

    def __init__(self, message: str, frame: Frame | None = None) -> None:
        super().__init__(message)
        self.frame = frame


@dataclass(frozen=True)
class Frame:
    """One DC-09 message, already decrypted if it was encrypted."""

    msg_id: str
    """Protocol token without the ``*`` (``ADM-CID``, ``SIA-DCS``, ``NULL`` ...)."""
    sequence: str
    receiver: str | None
    line: str | None
    account: str
    data: str
    """Content of the data block after the ``#acct|`` prefix (e.g. ``1130 01 015``)."""
    extended: tuple[str, ...] = ()
    """Extended data blocks (``[X...]``, ``[V...]``) without brackets."""
    timestamp: datetime | None = None
    encrypted: bool = False
    crc_ok: bool = True
    length_ok: bool = True
    raw: bytes = field(default=b"", repr=False)

    @property
    def valid(self) -> bool:
        return self.crc_ok and self.length_ok


_RE_HEADER = re.compile(
    r'^"(?P<enc>\*)?(?P<id>[A-Za-z0-9-]+)"'
    r"(?P<seq>\d{4})"
    r"(?:R(?P<rcvr>[0-9A-Fa-f]{1,6}))?"
    r"(?:L(?P<line>[0-9A-Fa-f]{1,6}))?"
    r"(?:#(?P<acct>[0-9A-Fa-f]{1,16}))?"
    r"\[(?P<rest>.*)$",
    re.S,
)

_RE_PLAIN_REST = re.compile(
    r"^(?P<data>[^\]]*)\]"
    r"(?P<xdata>(?:\[[^\]]*\])*)"
    r"(?:_(?P<ts>\d{2}:\d{2}:\d{2},\d{2}-\d{2}-\d{4}))?\s*$",
    re.S,
)

_RE_DECRYPTED = re.compile(
    r"^[^|\[\]]*\|(?P<data>[^\]]*)\]"
    r"(?P<xdata>(?:\[[^\]]*\])*)"
    r"(?:_(?P<ts>\d{2}:\d{2}:\d{2},\d{2}-\d{2}-\d{4}))?$",
    re.S,
)


def parse_key(value: str) -> bytes:
    """Parse an AES-128/192/256 key.

    Accepted forms: ``hex:<32|48|64 hex chars>``, ``ascii:<16|24|32 chars>``,
    or a bare value. A bare value of 32/48/64 hex characters is read as hex;
    use the ``ascii:`` prefix if your panel's key is literally such a string.
    """
    v = value.strip()
    if v.lower().startswith("ascii:"):
        raw = v[6:].encode("ascii")
    elif v.lower().startswith("hex:"):
        try:
            raw = bytes.fromhex(v[4:])
        except ValueError as exc:
            raise ValueError("AES key is not valid hex") from exc
    elif len(v) in (32, 48, 64) and all(c in string.hexdigits for c in v):
        raw = bytes.fromhex(v)
    else:
        raw = v.encode("ascii")
    if len(raw) not in (16, 24, 32):
        raise ValueError("AES key must be 128, 192 or 256 bits")
    return raw


def format_timestamp(when: datetime | None = None) -> str:
    when = (when or datetime.now(UTC)).astimezone(UTC)
    return when.strftime(_TS_FORMAT)


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, _TS_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None


def _split_xdata(xdata: str) -> tuple[str, ...]:
    return tuple(re.findall(r"\[([^\]]*)\]", xdata or ""))


def _strip_account_prefix(data: str) -> str:
    # Plain data blocks look like "#1234|1130 01 015"; keep only the payload.
    if data.startswith("#") and "|" in data:
        return data.split("|", 1)[1]
    return data.lstrip("|")


# ----------------------------------------------------------------- crypto


def _aes():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise DecryptionError(
            "encrypted DC-09 needs the 'cryptography' package: pip install dc09-receiver[aes]"
        ) from exc
    return Cipher, algorithms, modes


def encrypt_block(key: bytes, plaintext: str) -> str:
    """Pad *plaintext* to 16 bytes, AES-CBC encrypt with a zero IV, return hex."""
    Cipher, algorithms, modes = _aes()
    raw = plaintext.encode("ascii")
    pad_len = 16 - (len(raw) % 16)
    pad = "".join(secrets.choice(_PAD_ALPHABET) for _ in range(pad_len)).encode()
    enc = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
    return (enc.update(pad + raw) + enc.finalize()).hex().upper()


def decrypt_block(key: bytes, hextext: str) -> str:
    Cipher, algorithms, modes = _aes()
    try:
        data = bytes.fromhex(hextext.strip())
    except ValueError as exc:
        raise DecryptionError("ciphertext is not hex") from exc
    if not data or len(data) % 16:
        raise DecryptionError("ciphertext length is not a multiple of 16")
    dec = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).decryptor()
    plain = dec.update(data) + dec.finalize()
    try:
        return plain.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DecryptionError("wrong key (plaintext is not ASCII)") from exc


# ----------------------------------------------------------------- parsing


def parse_frame(raw: bytes, key_lookup: KeyLookup | None = None) -> Frame:
    """Parse one message. Raises :class:`FrameError` if it is not DC-09.

    A bad CRC or length does **not** raise: the frame is returned with
    ``crc_ok``/``length_ok`` set to ``False`` so the caller decides.
    """
    if not raw:
        raise FrameError("empty message")
    b = raw
    if b[0] == LF:
        b = b[1:]
    while b and b[-1] in (CR, LF, 0x00):
        b = b[:-1]
    if len(b) < 10:
        raise FrameError("message too short")

    try:
        header = b[:8].decode("ascii")
        crc_decl = int(header[:4], 16)
        len_decl = int(header[4:8], 16)
        body = b[8:]
    except (UnicodeDecodeError, ValueError):
        # Some communicators send the CRC as 2 raw bytes. Resync on the quote.
        i = b.find(b'"')
        if i < 0:
            raise FrameError("no DC-09 header found") from None
        body = b[i:]
        crc_decl = len_decl = -1

    crc_ok = crc_decl == crc16(body)
    length_ok = len_decl == len(body)

    try:
        text = body.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FrameError("message is not ASCII") from exc

    m = _RE_HEADER.match(text)
    if not m:
        raise FrameError("DC-09 header does not match")

    encrypted = bool(m.group("enc"))
    account = (m.group("acct") or "").upper()
    common = dict(
        msg_id=m.group("id").upper(),
        sequence=m.group("seq"),
        receiver=m.group("rcvr"),
        line=m.group("line"),
        account=account,
        encrypted=encrypted,
        crc_ok=crc_ok,
        length_ok=length_ok,
        raw=bytes(raw),
    )

    if encrypted:
        shell = Frame(data="", **common)
        key = key_lookup(account) if key_lookup else None
        if key is None:
            raise DecryptionError(f"no AES key for account {account!r}", shell)
        try:
            plain = decrypt_block(key, m.group("rest").rstrip("]"))
        except DecryptionError as exc:
            raise DecryptionError(str(exc), shell) from exc
        pm = _RE_DECRYPTED.match(plain)
        if not pm:
            raise DecryptionError("decrypted payload is malformed (wrong key?)", shell)
    else:
        pm = _RE_PLAIN_REST.match(m.group("rest"))
        if not pm:
            raise FrameError("data block is malformed")

    return Frame(
        data=_strip_account_prefix(pm.group("data")),
        extended=_split_xdata(pm.group("xdata")),
        timestamp=_parse_ts(pm.group("ts")),
        **common,
    )


# ----------------------------------------------------------------- building


def _wrap(body: str) -> bytes:
    raw = body.encode("ascii")
    return bytes([LF]) + f"{crc16(raw):04X}{len(raw):04X}".encode() + raw + bytes([CR])


def _routing(receiver: str | None, line: str | None, account: str | None) -> str:
    out = ""
    if receiver:
        out += f"R{receiver}"
    out += f"L{line or '0'}"
    if account:
        out += f"#{account}"
    return out


def build_message(
    msg_id: str,
    account: str,
    data: str,
    *,
    sequence: int | str = 1,
    receiver: str | None = None,
    line: str | None = "0",
    key: bytes | None = None,
    timestamp: datetime | None = None,
    extended: tuple[str, ...] = (),
    with_timestamp: bool = True,
) -> bytes:
    """Build a transmitter-side message (used by the simulator and the tests).

    *data* is the payload without the account prefix, e.g. ``"1130 01 015"``.
    """
    seq = f"{int(sequence) % 10000:04d}"
    xdata = "".join(f"[{x}]" for x in extended)
    ts = f"_{format_timestamp(timestamp)}" if (with_timestamp or key) else ""
    head = f'"{"*" if key else ""}{msg_id}"{seq}{_routing(receiver, line, account)}['
    if key:
        return _wrap(head + encrypt_block(key, f"|{data}]{xdata}{ts}"))
    prefix = f"#{account}|" if data else ""
    return _wrap(f"{head}{prefix}{data}]{xdata}{ts}")


def build_ack(
    frame: Frame,
    *,
    key: bytes | None = None,
    receiver: str | None = None,
    line: str | None = None,
    timestamp: datetime | None = None,
) -> bytes:
    """ACK echoing the sequence, receiver, line and account of *frame*.

    If the sequence or account do not match, the transmitter treats the ACK
    as foreign and retransmits the event.
    """
    routing = _routing(receiver or frame.receiver, line or frame.line, frame.account)
    seq = frame.sequence
    if frame.encrypted and key is not None:
        ts = format_timestamp(timestamp)
        return _wrap(f'"*ACK"{seq}{routing}[' + encrypt_block(key, f"|]_{ts}"))
    return _wrap(f'"ACK"{seq}{routing}[]')


def build_nak(
    *, receiver: str | None = None, line: str | None = None, timestamp: datetime | None = None
) -> bytes:
    """NAK carrying the receiver time (sent when the message timestamp is out of window)."""
    return _wrap(f'"NAK"0000R{receiver or "0"}L{line or "0"}A0[]_{format_timestamp(timestamp)}')


def build_duh(frame: Frame, *, receiver: str | None = None, line: str | None = None) -> bytes:
    """DUH: message understood as DC-09 but the receiver cannot process it."""
    routing = _routing(receiver or frame.receiver, line or frame.line, frame.account)
    return _wrap(f'"DUH"{frame.sequence}{routing}[]')
