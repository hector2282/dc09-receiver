"""Turn a DC-09 frame into normalized alarm events."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from . import codes
from .frame import Frame

__all__ = ["Event", "decode_cid", "decode_sia", "events_from_frame"]


@dataclass
class Event:
    account: str
    protocol: str
    """``ADM-CID``, ``SIA-DCS``, ``NULL`` or whatever token the panel sent."""
    code: str | None
    category: str
    """alarm | trouble | supervisory | openclose | test | info | link | unknown."""
    description: str
    qualifier: str | None = None
    """Contact ID: ``new`` | ``restore`` | ``status``. SIA: ``None``."""
    partition: int | None = None
    zone: int | None = None
    user: int | None = None
    arming: str | None = None
    """``away`` | ``stay`` | ``disarmed`` when the event says so, else ``None``."""
    heartbeat: bool = False
    """True for link keep-alives and periodic tests (supervision only)."""
    sequence: str | None = None
    receiver: str | None = None
    line: str | None = None
    panel_time: datetime | None = None
    received_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    remote_addr: str | None = None
    transport: str | None = None
    encrypted: bool = False
    crc_ok: bool = True
    account_known: bool | None = None
    account_name: str | None = None
    zone_name: str | None = None
    raw: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        for k in ("panel_time", "received_at"):
            if out[k] is not None:
                out[k] = out[k].isoformat()
        return out


_QUALIFIER = {"1": "new", "3": "restore", "6": "status"}

# "1130 01 015" or "113001015"; partition/zone may contain hex digits on some panels.
_RE_CID = re.compile(r"^\s*(?P<q>[136])(?P<code>\d{3})\s?(?P<part>[0-9A-Fa-f]{2})\s?(?P<zone>[0-9A-Fa-f]{3})")


def _int(value: str) -> int | None:
    try:
        return int(value, 10)
    except ValueError:
        try:
            return int(value, 16)
        except ValueError:
            return None


def decode_cid(data: str, lang: str = "en") -> dict[str, Any] | None:
    m = _RE_CID.match(data)
    if not m:
        return None
    q, code = m.group("q"), m.group("code")
    category, description = codes.describe_cid(code, q, lang)
    out: dict[str, Any] = {
        "code": q + code,
        "qualifier": _QUALIFIER[q],
        "category": category,
        "description": description,
        "partition": _int(m.group("part")),
        "heartbeat": code in codes.CID_PERIODIC,
    }
    number = _int(m.group("zone"))
    if code in codes.CID_OPEN_CLOSE:
        # For open/close the 3-digit field is the user number, not a zone.
        out["user"] = number
        if q == "1":
            out["arming"] = "disarmed"
        else:
            out["arming"] = "stay" if code in codes.CID_STAY else "away"
    else:
        out["zone"] = number
    return out


_RE_SIA_TOKEN = re.compile(r"(?P<mod>ri|id|pi|ti)(?P<mval>[0-9:]+)|(?P<code>[A-Z]{2})(?P<addr>\d{0,4})")


def decode_sia(data: str, lang: str = "en") -> list[dict[str, Any]]:
    """Decode a SIA DCS payload such as ``Nri1/BA01`` (may hold several events)."""
    body = data.strip()
    # Optional block marker: "N" (new event) or "O" (old event), followed by
    # a modifier ("ri", "id" ...) or a 2-letter code. "NL01"/"OP01" alone are
    # event codes, not markers, so only strip when what follows makes sense.
    if re.match(r"^[NO](?:ri|id|pi|ti|[A-Z]{2})", body):
        body = body[1:]
    events: list[dict[str, Any]] = []
    partition: int | None = None
    user: int | None = None
    for part in re.split(r"[/]", body):
        for m in _RE_SIA_TOKEN.finditer(part):
            if m.group("mod"):
                mod, val = m.group("mod"), m.group("mval")
                if mod == "ri":
                    partition = _int(val)
                elif mod == "id":
                    user = _int(val)
                continue
            code = m.group("code")
            addr = _int(m.group("addr")) if m.group("addr") else None
            category, description = codes.describe_sia(code, lang)
            ev: dict[str, Any] = {
                "code": code,
                "category": category,
                "description": description,
                "partition": partition,
                "heartbeat": code in codes.SIA_PERIODIC,
            }
            if code in codes.SIA_ARMED_AWAY:
                ev["arming"] = "away"
            elif code in codes.SIA_ARMED_STAY:
                ev["arming"] = "stay"
            elif code in codes.SIA_DISARMED:
                ev["arming"] = "disarmed"
            if category == "openclose":
                ev["user"] = addr if addr is not None else user
            else:
                ev["zone"] = addr
                if user is not None:
                    ev["user"] = user
            events.append(ev)
    return events


def events_from_frame(frame: Frame, lang: str = "en") -> list[Event]:
    """Decode *frame*. Unreadable payloads produce one ``unknown`` event (never dropped)."""
    base = dict(
        account=frame.account,
        protocol=frame.msg_id,
        sequence=frame.sequence,
        receiver=frame.receiver,
        line=frame.line,
        panel_time=frame.timestamp,
        encrypted=frame.encrypted,
        crc_ok=frame.crc_ok,
        raw=frame.raw.decode("ascii", "replace").strip(),
    )
    if frame.msg_id == "NULL":
        text = "Prueba de enlace (keep-alive)" if lang == "es" else "Link test (keep-alive)"
        return [Event(code=None, category="link", description=text, heartbeat=True, **base)]

    decoded: list[dict[str, Any]] = []
    if "CID" in frame.msg_id:
        one = decode_cid(frame.data, lang)
        decoded = [one] if one else []
    elif "SIA" in frame.msg_id:
        decoded = decode_sia(frame.data, lang)

    if not decoded:
        text = "Mensaje no interpretado" if lang == "es" else "Unrecognized payload"
        return [
            Event(
                code=None,
                category="unknown",
                description=f"{text} ({frame.msg_id}): {frame.data[:120]}",
                **base,
            )
        ]
    return [Event(**base, **d) for d in decoded]
