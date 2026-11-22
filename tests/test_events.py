import pytest

from dc09_receiver.events import decode_cid, decode_sia, events_from_frame
from dc09_receiver.frame import build_message, parse_frame


def ev(msg_id, data, lang="en"):
    return events_from_frame(parse_frame(build_message(msg_id, "1234", data)), lang)


def test_cid_burglary():
    (e,) = ev("ADM-CID", "1130 01 015")
    assert (e.code, e.category, e.qualifier, e.partition, e.zone) == ("1130", "alarm", "new", 1, 15)
    assert e.description == "Burglary"


def test_cid_restore_is_not_an_alarm():
    (e,) = ev("ADM-CID", "3130 01 015")
    assert e.qualifier == "restore" and e.category == "info"
    assert e.description.startswith("Restore")


@pytest.mark.parametrize(
    ("data", "arming", "user"),
    [("1401 01 003", "disarmed", 3), ("3401 01 003", "away", 3), ("3441 02 001", "stay", 1)],
)
def test_cid_open_close_qualifier_is_inverted(data, arming, user):
    (e,) = ev("ADM-CID", data)
    assert e.category == "openclose"
    assert e.arming == arming
    assert e.user == user and e.zone is None


def test_cid_without_spaces():
    d = decode_cid("113001015")
    assert d["code"] == "1130" and d["zone"] == 15


def test_cid_periodic_test_is_heartbeat():
    (e,) = ev("ADM-CID", "1602 00 000")
    assert e.heartbeat and e.category == "test"
    (m,) = ev("ADM-CID", "1601 00 000")
    assert not m.heartbeat


def test_cid_unknown_code_is_kept():
    (e,) = ev("ADM-CID", "1999 01 001")
    assert e.category == "info" and "999" in e.description


def test_spanish_descriptions():
    (e,) = ev("ADM-CID", "1130 01 015", lang="es")
    assert e.description == "Robo"
    (d,) = ev("ADM-CID", "1401 01 003", lang="es")
    assert d.description.startswith("Desarmado")


def test_sia_burglary_with_partition():
    (e,) = ev("SIA-DCS", "Nri1/BA01")
    assert (e.code, e.category, e.partition, e.zone) == ("BA", "alarm", 1, 1)


def test_sia_multiple_events():
    events = decode_sia("Nri2/BA05/TA06")
    assert [x["code"] for x in events] == ["BA", "TA"]
    assert all(x["partition"] == 2 for x in events)


@pytest.mark.parametrize(
    ("data", "arming"), [("Nri1/CL01", "away"), ("Nri1/OP01", "disarmed"), ("NL01", "stay")]
)
def test_sia_arming(data, arming):
    (e,) = ev("SIA-DCS", data)
    assert e.arming == arming


def test_sia_user_modifier():
    (e,) = decode_sia("Nid12/OP")
    assert e["user"] == 12 and e["arming"] == "disarmed"


def test_sia_periodic_test():
    (e,) = ev("SIA-DCS", "NRP")
    assert e.heartbeat


def test_null_is_link_heartbeat():
    (e,) = ev("NULL", "")
    assert e.category == "link" and e.heartbeat


def test_unreadable_payload_is_not_dropped():
    (e,) = ev("ADM-CID", "garbage")
    assert e.category == "unknown" and "garbage" in e.description


def test_to_dict_is_json_friendly():
    import json

    (e,) = ev("ADM-CID", "1130 01 015")
    json.dumps(e.to_dict())
