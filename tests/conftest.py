import pytest

from dc09_receiver.config import Account, Config

# Fictitious test data only. Do not put real account numbers or keys here.
TEST_KEY_HEX = "000102030405060708090A0B0C0D0E0F"


@pytest.fixture
def key() -> bytes:
    return bytes.fromhex(TEST_KEY_HEX)


@pytest.fixture
def config(key: bytes) -> Config:
    cfg = Config(host="127.0.0.1", port=0, sinks=[])
    cfg.accounts = {
        "1234": Account("1234", name="Demo warehouse", zones={15: "Back door"}, supervision_minutes=10),
        "ABCD": Account("ABCD", name="Encrypted demo", key=key),
    }
    return cfg
