"""Configuration (TOML file and/or environment variables)."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .frame import parse_key

__all__ = ["Account", "Config", "SinkConfig", "load_config"]


@dataclass
class Account:
    account: str
    name: str | None = None
    key: bytes | None = None
    supervision_minutes: float | None = None
    zones: dict[int, str] = field(default_factory=dict)


@dataclass
class SinkConfig:
    type: str
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class Config:
    host: str = "0.0.0.0"
    port: int = 9500
    tcp: bool = True
    udp: bool = True
    receiver_number: str | None = None
    """``R`` field used in ACKs; ``None`` echoes the value the panel sent."""
    line_prefix: str | None = None
    """``L`` field used in ACKs; ``None`` echoes the value the panel sent."""
    accept_unknown_accounts: bool = True
    accept_bad_crc: bool = False
    deliver_heartbeats: bool = False
    """Forward keep-alives / periodic tests to sinks (they always feed supervision)."""
    timestamp_window: tuple[int, int] | None = (-40, 20)
    """Allowed (min, max) seconds between panel time and receiver time.
    Enforced on encrypted messages (required by DC-09); ``None`` disables it."""
    language: str = "en"
    idle_timeout_seconds: float = 20 * 60
    dedup_window_seconds: float = 300
    supervision_grace_seconds: float = 60
    log_level: str = "INFO"
    accounts: dict[str, Account] = field(default_factory=dict)
    sinks: list[SinkConfig] = field(default_factory=lambda: [SinkConfig("stdout")])

    def key_for(self, account: str) -> bytes | None:
        acc = self.accounts.get(account.upper())
        return acc.key if acc else None


def _resolve_secret(table: dict[str, Any], name: str) -> str | None:
    """Read ``name`` directly or from the env var named by ``name_env``."""
    env_name = table.get(f"{name}_env")
    if env_name:
        value = os.environ.get(env_name)
        if value is None:
            raise ValueError(f"environment variable {env_name!r} is not set")
        return value
    return table.get(name)


def _account(table: dict[str, Any]) -> Account:
    number = str(table["account"]).upper()
    if not all(c in "0123456789ABCDEF" for c in number) or not 1 <= len(number) <= 16:
        raise ValueError(f"account {number!r}: DC-09 accounts are 1-16 hex digits (0-9, A-F)")
    key = _resolve_secret(table, "key")
    return Account(
        account=number,
        name=table.get("name"),
        key=parse_key(key) if key else None,
        supervision_minutes=table.get("supervision_minutes"),
        zones={int(k): str(v) for k, v in (table.get("zones") or {}).items()},
    )


def load_config(path: str | Path | None = None) -> Config:
    data: dict[str, Any] = {}
    if path:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)

    r = data.get("receiver", {})
    cfg = Config()
    for name in (
        "host",
        "port",
        "tcp",
        "udp",
        "receiver_number",
        "line_prefix",
        "accept_unknown_accounts",
        "accept_bad_crc",
        "deliver_heartbeats",
        "language",
        "idle_timeout_seconds",
        "dedup_window_seconds",
        "supervision_grace_seconds",
        "log_level",
    ):
        if name in r:
            setattr(cfg, name, r[name])
    if "timestamp_window" in r:
        tw = r["timestamp_window"]
        cfg.timestamp_window = (int(tw[0]), int(tw[1])) if tw else None

    # Environment overrides (handy in containers).
    env = os.environ
    if "DC09_HOST" in env:
        cfg.host = env["DC09_HOST"]
    if "DC09_PORT" in env:
        cfg.port = int(env["DC09_PORT"])
    if "DC09_LOG_LEVEL" in env:
        cfg.log_level = env["DC09_LOG_LEVEL"]

    for table in data.get("accounts", []):
        acc = _account(table)
        cfg.accounts[acc.account] = acc

    if "sinks" in data:
        cfg.sinks = []
        for table in data["sinks"]:
            opts = {k: v for k, v in table.items() if k != "type"}
            if "secret" in opts or "secret_env" in opts:
                opts["secret"] = _resolve_secret(opts, "secret")
                opts.pop("secret_env", None)
            cfg.sinks.append(SinkConfig(type=table["type"], options=opts))

    if cfg.language not in ("en", "es"):
        raise ValueError("receiver.language must be 'en' or 'es'")
    return cfg
