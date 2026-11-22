"""Where decoded events go.

Every sink has its own bounded queue and worker task, so a slow webhook can
never delay the ACK to the panel (a late ACK makes the panel retransmit).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import sys
import urllib.request
from pathlib import Path
from typing import Any, TextIO

from .config import SinkConfig
from .events import Event

__all__ = ["CallbackSink", "JsonlFileSink", "Sink", "StdoutSink", "WebhookSink", "build_sinks"]

log = logging.getLogger("dc09_receiver.sinks")


class Sink:
    """Base class. Subclasses implement :meth:`deliver`."""

    name = "sink"

    def __init__(self, queue_size: int = 10_000) -> None:
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=queue_size)
        self._task: asyncio.Task[None] | None = None
        self.dropped = 0

    def submit(self, event: Event) -> None:
        try:
            self._queue.put_nowait(event.to_dict())
        except asyncio.QueueFull:
            self.dropped += 1
            log.error("%s queue full, dropping event for account %s", self.name, event.account)

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name=f"sink:{self.name}")

    async def stop(self, timeout: float = 5.0) -> None:
        try:
            await asyncio.wait_for(self._queue.join(), timeout)
        except TimeoutError:
            log.warning("%s: %d events not delivered at shutdown", self.name, self._queue.qsize())
        if self._task:
            self._task.cancel()

    async def _run(self) -> None:
        while True:
            item = await self._queue.get()
            try:
                await self.deliver(item)
            except Exception:
                log.exception("%s failed to deliver event", self.name)
            finally:
                self._queue.task_done()

    async def deliver(self, item: dict[str, Any]) -> None:  # pragma: no cover - abstract
        raise NotImplementedError


class StdoutSink(Sink):
    """One JSON object per line on stdout (pipe it to jq, Vector, Fluent Bit ...)."""

    name = "stdout"

    def __init__(self, stream: TextIO | None = None, **kw: Any) -> None:
        super().__init__(**kw)
        self.stream = stream or sys.stdout

    async def deliver(self, item: dict[str, Any]) -> None:
        self.stream.write(json.dumps(item, ensure_ascii=False) + "\n")
        self.stream.flush()


class JsonlFileSink(Sink):
    """Append events to a JSON Lines file."""

    name = "file"

    def __init__(self, path: str, **kw: Any) -> None:
        super().__init__(**kw)
        self.path = Path(path)

    async def deliver(self, item: dict[str, Any]) -> None:
        line = json.dumps(item, ensure_ascii=False) + "\n"
        await asyncio.to_thread(self._append, line)

    def _append(self, line: str) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)


class WebhookSink(Sink):
    """POST each event as JSON, optionally signed with HMAC-SHA256.

    Header ``X-DC09-Signature: sha256=<hex>`` is computed over the raw body.
    Failed deliveries are retried with exponential backoff.
    """

    name = "webhook"

    def __init__(
        self,
        url: str,
        secret: str | None = None,
        timeout: float = 10.0,
        retries: int = 5,
        headers: dict[str, str] | None = None,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        if not url.startswith(("http://", "https://")):
            raise ValueError("webhook url must start with http:// or https://")
        self.url = url
        self.secret = secret.encode() if secret else None
        self.timeout = timeout
        self.retries = retries
        self.headers = headers or {}

    def sign(self, body: bytes) -> str | None:
        if not self.secret:
            return None
        return "sha256=" + hmac.new(self.secret, body, hashlib.sha256).hexdigest()

    async def deliver(self, item: dict[str, Any]) -> None:
        body = json.dumps(item, ensure_ascii=False).encode()
        delay = 1.0
        for attempt in range(self.retries + 1):
            try:
                await asyncio.to_thread(self._post, body)
                return
            except Exception as exc:  # noqa: BLE001
                if attempt == self.retries:
                    log.error("webhook gave up after %d attempts: %s", attempt + 1, exc)
                    return
                log.warning("webhook attempt %d failed: %s (retry in %.0fs)", attempt + 1, exc, delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60)

    def _post(self, body: bytes) -> None:
        req = urllib.request.Request(self.url, data=body, method="POST")  # noqa: S310 - scheme checked
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "dc09-receiver")
        for k, v in self.headers.items():
            req.add_header(k, v)
        sig = self.sign(body)
        if sig:
            req.add_header("X-DC09-Signature", sig)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            if resp.status >= 300:
                raise RuntimeError(f"HTTP {resp.status}")


class CallbackSink(Sink):
    """Call a Python coroutine or function for each event (library use)."""

    name = "callback"

    def __init__(self, func, **kw: Any) -> None:
        super().__init__(**kw)
        self.func = func

    async def deliver(self, item: dict[str, Any]) -> None:
        result = self.func(item)
        if asyncio.iscoroutine(result):
            await result


_TYPES = {"stdout": StdoutSink, "file": JsonlFileSink, "webhook": WebhookSink}


def build_sinks(configs: list[SinkConfig]) -> list[Sink]:
    sinks = []
    for sc in configs:
        cls = _TYPES.get(sc.type)
        if cls is None:
            raise ValueError(f"unknown sink type {sc.type!r} (expected one of {sorted(_TYPES)})")
        sinks.append(cls(**sc.options))
    return sinks
