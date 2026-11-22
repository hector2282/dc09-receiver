import json

from dc09_receiver.cli import main
from dc09_receiver.frame import build_message


def test_parse_command(capsys):
    raw = build_message("ADM-CID", "1234", "1130 01 015").decode()
    escaped = raw.replace("\n", "\\n").replace("\r", "\\r")
    assert main(["parse", escaped]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["frame"]["account"] == "1234"
    assert out["events"][0]["description"] == "Burglary"


def test_parse_command_rejects_garbage(capsys):
    assert main(["parse", "nope"]) == 2
