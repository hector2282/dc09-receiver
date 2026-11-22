import pytest

from dc09_receiver.config import load_config

SAMPLE = """
[receiver]
port = 9600
language = "es"
accept_unknown_accounts = false

[[accounts]]
account = "1234"
name = "Demo"
supervision_minutes = 10
zones = { 1 = "Front door", 2 = "Hall" }

[[accounts]]
account = "abcd"
key_env = "TEST_DC09_KEY"

[[sinks]]
type = "webhook"
url = "https://example.invalid/hook"
secret_env = "TEST_DC09_SECRET"
"""


def test_load_config(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_DC09_KEY", "00112233445566778899AABBCCDDEEFF")
    monkeypatch.setenv("TEST_DC09_SECRET", "s3cr3t")
    p = tmp_path / "c.toml"
    p.write_text(SAMPLE)
    cfg = load_config(p)
    assert cfg.port == 9600 and cfg.language == "es" and not cfg.accept_unknown_accounts
    assert cfg.accounts["1234"].zones == {1: "Front door", 2: "Hall"}
    assert cfg.key_for("abcd") == bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    assert cfg.sinks[0].options["secret"] == "s3cr3t"


def test_missing_env_var(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[[accounts]]\naccount = "1"\nkey_env = "DOES_NOT_EXIST_DC09"\n')
    with pytest.raises(ValueError):
        load_config(p)


def test_account_must_be_hex(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[[accounts]]\naccount = "warehouse"\n')
    with pytest.raises(ValueError, match="hex"):
        load_config(p)


def test_defaults_without_file():
    cfg = load_config(None)
    assert cfg.port == 9500 and cfg.sinks[0].type == "stdout"
