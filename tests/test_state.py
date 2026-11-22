from dc09_receiver.state import ArmingTracker, Deduplicator, Supervisor


def test_dedup_window():
    d = Deduplicator(window_seconds=10)
    assert not d.is_duplicate("1234", "0001", "x", now=0)
    assert d.is_duplicate("1234", "0001", "x", now=5)
    assert not d.is_duplicate("1234", "0002", "x", now=5)
    assert not d.is_duplicate("1234", "0001", "x", now=30)


def test_dedup_bounded():
    d = Deduplicator(window_seconds=1000, max_entries=10)
    for i in range(100):
        d.is_duplicate("1234", f"{i:04d}", "x", now=i)
    assert len(d._seen) <= 10


def test_supervision_lost_and_restored():
    s = Supervisor(grace_seconds=60)
    s.watch("1234", 600, now=0)
    assert s.check(now=1000) == []
    lost = s.check(now=1300)
    assert lost and lost[0][0] == "1234"
    assert s.check(now=1400) == []  # reported once
    assert s.seen("1234", now=1500) is True
    assert s.seen("1234", now=1600) is False


def test_unwatched_account_is_ignored():
    s = Supervisor()
    assert s.seen("FFFF") is False


def test_arming_tracker():
    t = ArmingTracker()
    assert t.get("1234", 1) is None
    assert t.update("1234", 1, "away") is None
    assert t.update("1234", 1, "away") is None
    assert t.update("1234", 1, "disarmed") == "away"
    assert t.snapshot() == {"1234": {"1": "disarmed"}}
