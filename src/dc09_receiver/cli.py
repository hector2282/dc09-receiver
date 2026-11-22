"""Command line: ``dc09-receiver serve | send | parse``."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import socket
import sys

from . import __version__
from .config import load_config
from .events import events_from_frame
from .frame import FrameError, build_message, parse_frame, parse_key
from .server import Receiver
from .sinks import build_sinks


def _serve(args: argparse.Namespace) -> int:
    cfg = load_config(args.config or os.environ.get("DC09_CONFIG") or None)
    if args.port is not None:
        cfg.port = args.port
    logging.basicConfig(
        level=cfg.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,  # stdout is reserved for the JSON event stream
    )
    receiver = Receiver(cfg, build_sinks(cfg.sinks))

    async def run() -> None:
        loop = asyncio.get_running_loop()
        stop = asyncio.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:  # pragma: no cover - Windows
                pass
        await receiver.start()
        await stop.wait()
        await receiver.stop()

    asyncio.run(run())
    return 0


def _send(args: argparse.Namespace) -> int:
    """Act as a transmitter: build one message, send it and print the reply."""
    key = parse_key(args.key) if args.key else None
    if args.null:
        msg_id, data = "NULL", ""
    elif args.sia:
        msg_id, data = "SIA-DCS", args.sia
    else:
        msg_id, data = "ADM-CID", args.cid
    msg = build_message(
        msg_id,
        args.account.upper(),
        data,
        sequence=args.sequence,
        receiver=args.receiver,
        line=args.line,
        key=key,
    )
    print(f">>> {msg!r}")
    kind = socket.SOCK_DGRAM if args.udp else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as s:
        s.settimeout(args.timeout)
        if args.udp:
            s.sendto(msg, (args.host, args.port))
            reply, _ = s.recvfrom(4096)
        else:
            s.connect((args.host, args.port))
            s.sendall(msg)
            reply = s.recv(4096)
    print(f"<<< {reply!r}")
    try:
        frame = parse_frame(reply, key_lookup=lambda _a: key)
    except FrameError as exc:
        print(f"reply is not valid DC-09: {exc}", file=sys.stderr)
        return 2
    print(f"reply: {frame.msg_id} seq={frame.sequence} crc_ok={frame.crc_ok}")
    return 0 if frame.msg_id == "ACK" else 1


def _parse(args: argparse.Namespace) -> int:
    raw = args.message.encode().decode("unicode_escape").encode("latin-1")
    key = parse_key(args.key) if args.key else None
    try:
        frame = parse_frame(raw, key_lookup=lambda _a: key)
    except FrameError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out = {
        "frame": {
            "id": frame.msg_id,
            "sequence": frame.sequence,
            "receiver": frame.receiver,
            "line": frame.line,
            "account": frame.account,
            "data": frame.data,
            "extended": list(frame.extended),
            "encrypted": frame.encrypted,
            "crc_ok": frame.crc_ok,
            "length_ok": frame.length_ok,
            "timestamp": frame.timestamp.isoformat() if frame.timestamp else None,
        },
        "events": [e.to_dict() for e in events_from_frame(frame, args.lang)],
    }
    for ev in out["events"]:
        ev.pop("received_at", None)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dc09-receiver", description="ANSI/SIA DC-09 alarm receiver")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the receiver")
    s.add_argument("-c", "--config", help="TOML config file (default: $DC09_CONFIG, else built-in defaults)")
    s.add_argument("-p", "--port", type=int, help="override the listening port")
    s.set_defaults(func=_serve)

    t = sub.add_parser("send", help="send a test message (panel simulator)")
    t.add_argument("--host", default="127.0.0.1")
    t.add_argument("--port", type=int, default=9500)
    t.add_argument("--account", default="1234")
    g = t.add_mutually_exclusive_group()
    g.add_argument("--cid", default="1130 01 015", help="Contact ID payload, e.g. '1130 01 015'")
    g.add_argument("--sia", help="SIA DCS payload, e.g. 'Nri1/BA01'")
    g.add_argument("--null", action="store_true", help="send a NULL keep-alive")
    t.add_argument("--sequence", type=int, default=1)
    t.add_argument("--receiver", default=None, help="R field")
    t.add_argument("--line", default="0", help="L field")
    t.add_argument("--key", help="AES key (hex or raw) to send an encrypted message")
    t.add_argument("--udp", action="store_true")
    t.add_argument("--timeout", type=float, default=5.0)
    t.set_defaults(func=_send)

    q = sub.add_parser("parse", help="decode a raw message (use \\n and \\r escapes)")
    q.add_argument("message")
    q.add_argument("--key")
    q.add_argument("--lang", default="en", choices=["en", "es"])
    q.set_defaults(func=_parse)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
