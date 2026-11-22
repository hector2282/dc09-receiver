import asyncio
import hashlib
import hmac
import json
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from dc09_receiver.frame import build_message, parse_frame
from dc09_receiver.server import Receiver
from dc09_receiver.sinks import CallbackSink, WebhookSink


class Collect(CallbackSink):
    def __init__(self):
        self.items = []
        super().__init__(self.items.append)


def make(config):
    sink = Collect()
    return Receiver(config, [sink]), sink


async def drain(rx):
    for s in rx.sinks:
        await s._queue.join()


def test_handle_returns_ack_and_enriches(config):
    async def run():
        rx, sink = make(config)
        await rx.start()
        ack = rx.handle(build_message("ADM-CID", "1234", "1130 01 015", sequence=5), "192.0.2.10")
        assert parse_frame(ack).msg_id == "ACK"
        await drain(rx)
        await rx.stop()
        return sink.items

    (item,) = asyncio.run(run())
    assert item["account_name"] == "Demo warehouse"
    assert item["zone_name"] == "Back door"
    assert item["remote_addr"] == "192.0.2.10"
    assert item["account_known"] is True


def test_retransmission_acked_but_delivered_once(config):
    async def run():
        rx, sink = make(config)
        await rx.start()
        msg = build_message("ADM-CID", "1234", "1130 01 015", sequence=9)
        assert rx.handle(msg) and rx.handle(msg) and rx.handle(msg)
        await drain(rx)
        await rx.stop()
        return sink.items, rx.stats

    items, stats = asyncio.run(run())
    assert len(items) == 1 and stats["duplicates"] == 2


def test_bad_crc_not_acked(config):
    rx, _ = make(config)
    msg = build_message("ADM-CID", "1234", "1130 01 015")
    bad = msg[:1] + b"0000" + msg[5:]
    assert rx.handle(bad) is None
    config.accept_bad_crc = True
    assert parse_frame(Receiver(config, []).handle(bad)).msg_id == "ACK"


def test_unknown_account_policy(config):
    msg = build_message("ADM-CID", "BEEF", "1130 01 015")
    assert parse_frame(Receiver(config, []).handle(msg)).msg_id == "ACK"
    config.accept_unknown_accounts = False
    assert parse_frame(Receiver(config, []).handle(msg)).msg_id == "DUH"


def test_heartbeats_feed_supervision_but_not_sinks(config):
    async def run():
        rx, sink = make(config)
        await rx.start()
        rx.handle(build_message("NULL", "1234", ""))
        rx.handle(build_message("ADM-CID", "1234", "1602 00 000", sequence=2))
        await drain(rx)
        await rx.stop()
        return sink.items, rx.stats

    items, stats = asyncio.run(run())
    assert items == [] and stats["heartbeats"] == 2


def test_supervision_lost_event(config):
    async def run():
        rx, sink = make(config)
        await rx.start()
        w = rx.supervisor._watches["1234"]
        w.last_seen -= 3600
        for account, silent in rx.supervisor.check():
            rx._emit(rx._receiver_event(account, "SUPERVISION_LOST", "trouble", silent))
        rx.handle(build_message("ADM-CID", "1234", "1130 01 015"))
        await drain(rx)
        await rx.stop()
        return sink.items

    items = asyncio.run(run())
    assert [i["code"] for i in items] == ["SUPERVISION_LOST", "SUPERVISION_RESTORED", "1130"]


def test_encrypted_message_acked_encrypted(config, key):
    rx, _ = make(config)
    ack = rx.handle(build_message("SIA-DCS", "ABCD", "Nri1/BA01", key=key))
    assert b'"*ACK"' in ack


def test_encrypted_stale_timestamp_gets_nak(config, key):
    old = datetime.now(UTC) - timedelta(minutes=10)
    rx, _ = make(config)
    reply = rx.handle(build_message("SIA-DCS", "ABCD", "Nri1/BA01", key=key, timestamp=old))
    assert parse_frame(reply).msg_id == "NAK"


def test_encrypted_without_configured_key_gets_duh(config, key):
    rx, _ = make(config)
    reply = rx.handle(build_message("SIA-DCS", "9999", "Nri1/BA01", key=key))
    assert parse_frame(reply).msg_id == "DUH"


def test_arming_state_tracked(config):
    rx, _ = make(config)
    rx.handle(build_message("ADM-CID", "1234", "3401 01 002", sequence=1))
    assert rx.arming.get("1234", 1) == "away"
    rx.handle(build_message("ADM-CID", "1234", "1401 01 002", sequence=2))
    assert rx.arming.get("1234", 1) == "disarmed"


@pytest.mark.parametrize("transport", ["tcp", "udp"])
def test_end_to_end_socket(config, transport):
    async def run():
        rx, sink = make(config)
        await rx.start()
        msg = build_message("ADM-CID", "1234", "1130 01 015", sequence=77)
        if transport == "tcp":
            reader, writer = await asyncio.open_connection("127.0.0.1", rx.ports[0])
            writer.write(msg)
            await writer.drain()
            reply = await asyncio.wait_for(reader.readuntil(b"\r"), 5)
            # second message on the same persistent connection
            writer.write(build_message("ADM-CID", "1234", "3130 01 015", sequence=78))
            await writer.drain()
            reply2 = await asyncio.wait_for(reader.readuntil(b"\r"), 5)
            writer.close()
            await writer.wait_closed()
            assert parse_frame(reply2).sequence == "0078"
        else:
            loop = asyncio.get_running_loop()
            fut = loop.create_future()

            class P(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    fut.set_result(data)

            tr, _ = await loop.create_datagram_endpoint(P, remote_addr=("127.0.0.1", rx.udp_port))
            tr.sendto(msg)
            reply = await asyncio.wait_for(fut, 5)
            tr.close()
        await drain(rx)
        await rx.stop()
        return reply, sink.items

    reply, items = asyncio.run(run())
    f = parse_frame(reply)
    assert f.msg_id == "ACK" and f.sequence == "0077"
    assert items[0]["code"] == "1130"


def test_webhook_sink_signs_body():
    received = {}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received["body"] = body
            received["sig"] = self.headers["X-DC09-Signature"]
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=httpd.handle_request, daemon=True)
    t.start()

    async def run():
        sink = WebhookSink(f"http://127.0.0.1:{httpd.server_port}/hook", secret="test-secret", retries=0)
        await sink.start()
        await sink.deliver({"account": "1234", "code": "1130"})
        await sink.stop()

    asyncio.run(run())
    t.join(5)
    httpd.server_close()
    expected = "sha256=" + hmac.new(b"test-secret", received["body"], hashlib.sha256).hexdigest()
    assert received["sig"] == expected
    assert json.loads(received["body"])["code"] == "1130"
