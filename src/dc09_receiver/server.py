"""Asyncio TCP + UDP receiver."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections import Counter
from datetime import UTC, datetime

from .config import Config
from .events import Event, events_from_frame
from .frame import (
    DecryptionError,
    Frame,
    FrameError,
    build_ack,
    build_duh,
    build_nak,
    parse_frame,
)
from .sinks import Sink
from .state import ArmingTracker, Deduplicator, Supervisor

__all__ = ["Receiver"]

log = logging.getLogger("dc09_receiver")

MAX_MESSAGE = 4096
SUPERVISION_CHECK_SECONDS = 30


class Receiver:
    """Receive DC-09 messages, answer them and hand events to the sinks.

    The order inside :meth:`handle` matters: the response is computed first
    and nothing slow (I/O, sinks) happens before it is sent.
    """

    def __init__(self, config: Config, sinks: list[Sink]) -> None:
        self.config = config
        self.sinks = sinks
        self.dedup = Deduplicator(config.dedup_window_seconds)
        self.supervisor = Supervisor(grace_seconds=config.supervision_grace_seconds)
        self.arming = ArmingTracker()
        self.stats: Counter[str] = Counter()
        self._servers: list[asyncio.AbstractServer] = []
        self._udp: asyncio.DatagramTransport | None = None
        self._tasks: list[asyncio.Task[None]] = []
        for acc in config.accounts.values():
            if acc.supervision_minutes:
                self.supervisor.watch(acc.account, acc.supervision_minutes * 60)

    # ------------------------------------------------------------ core logic

    def handle(self, raw: bytes, remote_addr: str | None = None, transport: str = "tcp") -> bytes | None:
        """Process one message and return the bytes to answer (or None)."""
        self.stats["received"] += 1
        cfg = self.config
        try:
            frame = parse_frame(raw, key_lookup=cfg.key_for)
        except DecryptionError as exc:
            self.stats["decrypt_failed"] += 1
            log.warning("cannot decrypt message from %s: %s", remote_addr, exc)
            return (
                build_duh(exc.frame, receiver=cfg.receiver_number, line=cfg.line_prefix)
                if exc.frame
                else None
            )
        except FrameError as exc:
            self.stats["unparseable"] += 1
            log.warning("not a DC-09 message from %s (%s): %r", remote_addr, exc, raw[:120])
            return None

        if not frame.valid and not cfg.accept_bad_crc:
            # No answer: the panel retransmits, hopefully intact this time.
            self.stats["bad_crc"] += 1
            log.warning("bad CRC/length from %s account %s, ignored", remote_addr, frame.account)
            return None

        known = frame.account in cfg.accounts
        if not known and not cfg.accept_unknown_accounts:
            self.stats["unknown_account_rejected"] += 1
            log.warning("account %s from %s is not configured, rejected", frame.account, remote_addr)
            return build_duh(frame, receiver=cfg.receiver_number, line=cfg.line_prefix)

        if self._timestamp_out_of_window(frame):
            self.stats["nak_timestamp"] += 1
            log.warning("timestamp out of window from account %s: %s", frame.account, frame.timestamp)
            return build_nak(receiver=cfg.receiver_number, line=cfg.line_prefix)

        ack = build_ack(
            frame,
            key=cfg.key_for(frame.account) if frame.encrypted else None,
            receiver=cfg.receiver_number,
            line=cfg.line_prefix,
        )

        payload = frame.data + "".join(frame.extended)
        if frame.msg_id != "NULL" and self.dedup.is_duplicate(frame.account, frame.sequence, payload):
            self.stats["duplicates"] += 1
            log.info("retransmission from account %s seq %s, ACK only", frame.account, frame.sequence)
            return ack

        self._dispatch(frame, known, remote_addr, transport)
        return ack

    def _timestamp_out_of_window(self, frame: Frame) -> bool:
        window = self.config.timestamp_window
        if not (window and frame.encrypted and frame.timestamp):
            return False
        delta = (frame.timestamp - datetime.now(UTC)).total_seconds()
        return not (window[0] <= delta <= window[1])

    def _dispatch(self, frame: Frame, known: bool, remote_addr: str | None, transport: str) -> None:
        cfg = self.config
        account = cfg.accounts.get(frame.account)
        if self.supervisor.seen(frame.account):
            self._emit(self._receiver_event(frame.account, "SUPERVISION_RESTORED", "info"))

        for ev in events_from_frame(frame, cfg.language):
            ev.remote_addr = remote_addr
            ev.transport = transport
            ev.account_known = known
            if account:
                ev.account_name = account.name
                if ev.zone is not None:
                    ev.zone_name = account.zones.get(ev.zone)
            self.arming.update(ev.account, ev.partition, ev.arming)
            if ev.heartbeat:
                self.stats["heartbeats"] += 1
                if not cfg.deliver_heartbeats:
                    continue
            self.stats["events"] += 1
            log.info("account=%s %s zone=%s category=%s", ev.account, ev.description, ev.zone, ev.category)
            self._emit(ev)

    def _receiver_event(self, account: str, code: str, category: str, silent: float | None = None) -> Event:
        acc = self.config.accounts.get(account)
        es = self.config.language == "es"
        if code == "SUPERVISION_LOST":
            minutes = round((silent or 0) / 60)
            text = f"Sin comunicación hace {minutes} min" if es else f"No communication for {minutes} min"
        else:
            text = "Comunicación restablecida" if es else "Communication restored"
        return Event(
            account=account,
            protocol="RECEIVER",
            code=code,
            category=category,
            description=text,
            account_known=True,
            account_name=acc.name if acc else None,
        )

    def _emit(self, event: Event) -> None:
        for sink in self.sinks:
            sink.submit(event)

    async def _supervision_loop(self) -> None:
        while True:
            await asyncio.sleep(SUPERVISION_CHECK_SECONDS)
            for account, silent in self.supervisor.check():
                self.stats["supervision_lost"] += 1
                log.warning("account %s silent for %.0f s", account, silent)
                self._emit(self._receiver_event(account, "SUPERVISION_LOST", "trouble", silent))

    # ------------------------------------------------------------ transports

    async def _tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else None
        log.debug("TCP connection from %s", ip)
        try:
            while True:
                try:
                    raw = await asyncio.wait_for(reader.readuntil(b"\r"), self.config.idle_timeout_seconds)
                except asyncio.IncompleteReadError as exc:
                    raw = exc.partial
                    if not raw.strip():
                        break
                except asyncio.LimitOverrunError:
                    log.warning("oversized message from %s, closing", ip)
                    break
                except (TimeoutError, ConnectionError):
                    break
                # Panels keep the socket open between events and some send
                # stray LFs; skip blank reads instead of treating them as data.
                if not raw.strip(b"\r\n\x00"):
                    continue
                answer = self.handle(raw, ip, "tcp")
                if answer:
                    writer.write(answer)
                    await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    class _UdpProtocol(asyncio.DatagramProtocol):
        def __init__(self, receiver: Receiver) -> None:
            self.receiver = receiver
            self.transport: asyncio.DatagramTransport | None = None

        def connection_made(self, transport) -> None:  # type: ignore[override]
            self.transport = transport

        def datagram_received(self, data: bytes, addr) -> None:
            answer = self.receiver.handle(data, addr[0] if addr else None, "udp")
            if answer and self.transport:
                self.transport.sendto(answer, addr)

    async def start(self) -> None:
        cfg = self.config
        for sink in self.sinks:
            await sink.start()
        loop = asyncio.get_running_loop()
        if cfg.tcp:
            server = await asyncio.start_server(self._tcp_client, cfg.host, cfg.port, limit=MAX_MESSAGE)
            self._servers.append(server)
        if cfg.udp:
            self._udp, _ = await loop.create_datagram_endpoint(
                lambda: Receiver._UdpProtocol(self), local_addr=(cfg.host, cfg.port)
            )
        self._tasks.append(asyncio.create_task(self._supervision_loop()))
        log.info(
            "listening on %s:%s (%s), %d accounts configured",
            cfg.host,
            cfg.port,
            "+".join(t for t, on in (("tcp", cfg.tcp), ("udp", cfg.udp)) if on),
            len(cfg.accounts),
        )

    @property
    def ports(self) -> list[int]:
        """Actual bound TCP ports (useful when port=0 in tests)."""
        return [s.sockets[0].getsockname()[1] for s in self._servers if s.sockets]

    @property
    def udp_port(self) -> int | None:
        return self._udp.get_extra_info("sockname")[1] if self._udp else None

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for server in self._servers:
            server.close()
            await server.wait_closed()
        if self._udp:
            self._udp.close()
        for sink in self.sinks:
            await sink.stop()
        log.info("stopped: %s", dict(self.stats))

    async def serve_forever(self) -> None:
        await self.start()
        try:
            await asyncio.Event().wait()
        finally:
            await self.stop()
