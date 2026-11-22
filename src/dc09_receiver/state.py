"""In-memory state: retransmission dedup, supervision and arming state."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

__all__ = ["ArmingTracker", "Deduplicator", "Supervisor"]


class Deduplicator:
    """Drop retransmissions of a message the panel already sent.

    Transmitters resend the same message (same sequence and payload) when an
    ACK gets lost. We ACK every copy, but only deliver the first one.
    """

    def __init__(self, window_seconds: float = 300.0, max_entries: int = 50_000) -> None:
        self.window = window_seconds
        self.max_entries = max_entries
        self._seen: dict[tuple[str, str, str], float] = {}

    def is_duplicate(self, account: str, sequence: str, payload: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        key = (account, sequence, payload)
        seen = self._seen.get(key)
        self._seen[key] = now
        if len(self._seen) > self.max_entries:
            self._prune(now)
        return seen is not None and now - seen < self.window

    def _prune(self, now: float) -> None:
        self._seen = {k: t for k, t in self._seen.items() if now - t < self.window}
        while len(self._seen) > self.max_entries:  # pathological flood
            self._seen.pop(next(iter(self._seen)))


@dataclass
class _Watch:
    interval: float
    last_seen: float
    lost: bool = False


@dataclass
class Supervisor:
    """Detect panels that stopped reporting.

    A panel is declared lost when nothing (event or heartbeat) arrived for
    ``2 * interval + grace`` seconds: one missed heartbeat is normal on bad
    links, two in a row is not.
    """

    grace_seconds: float = 60.0
    _watches: dict[str, _Watch] = field(default_factory=dict)

    def watch(self, account: str, interval_seconds: float, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self._watches[account] = _Watch(interval=interval_seconds, last_seen=now)

    def seen(self, account: str, now: float | None = None) -> bool:
        """Record activity. Returns True if the account was lost and is now back."""
        w = self._watches.get(account)
        if w is None:
            return False
        w.last_seen = time.monotonic() if now is None else now
        if w.lost:
            w.lost = False
            return True
        return False

    def check(self, now: float | None = None) -> list[tuple[str, float]]:
        """Return ``(account, silent_seconds)`` for accounts that just went silent."""
        now = time.monotonic() if now is None else now
        newly_lost = []
        for account, w in self._watches.items():
            silent = now - w.last_seen
            if not w.lost and silent > 2 * w.interval + self.grace_seconds:
                w.lost = True
                newly_lost.append((account, silent))
        return newly_lost

    def status(self, now: float | None = None) -> dict[str, dict[str, float | bool]]:
        now = time.monotonic() if now is None else now
        return {
            a: {"lost": w.lost, "silent_seconds": round(now - w.last_seen, 1), "interval": w.interval}
            for a, w in self._watches.items()
        }


class ArmingTracker:
    """Remember the last arming state reported per (account, partition).

    DC-09 is one-way: you cannot ask a panel whether it is armed. But panels
    report every arm/disarm, so the last one we saw is the current state.
    It is ``None`` until the first open/close arrives.
    """

    def __init__(self) -> None:
        self._state: dict[tuple[str, int | None], str] = {}

    def update(self, account: str, partition: int | None, arming: str | None) -> str | None:
        """Store *arming*. Returns the previous state if it changed, else None."""
        if arming is None:
            return None
        key = (account, partition)
        previous = self._state.get(key)
        self._state[key] = arming
        return previous if previous != arming else None

    def get(self, account: str, partition: int | None = None) -> str | None:
        return self._state.get((account, partition))

    def snapshot(self) -> dict[str, dict[str, str]]:
        out: dict[str, dict[str, str]] = {}
        for (account, partition), state in self._state.items():
            out.setdefault(account, {})[str(partition if partition is not None else 0)] = state
        return out
