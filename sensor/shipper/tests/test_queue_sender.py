from __future__ import annotations

import gzip
import hashlib
import json
import random

import httpx
import pytest
import respx

from conftest import TOKEN

from sentinel_shipper.queue import DiskQueue
from sentinel_shipper.sender import Sender

URL = "https://sentinel.example.test/api/ingest"


def body(n: int = 0) -> dict:
    return {"sensor_id": "sensor-01", "devices": [], "windows": [
        {"device_hash": "dev-aaaaaa", "ts": 60 * n, "duration_s": 60, "bytes_in": n, "bytes_out": 0,
         "pkts": 0, "distinct_dests": 0, "distinct_ports": 0, "syn_ratio": 0.0, "score": None,
         "countries": {}}], "alerts": []}


class Clock:
    def __init__(self, t: float = 1_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


# --- queue ---------------------------------------------------------------------

def test_queue_survives_restart(tmp_path):
    q = DiskQueue(tmp_path)
    q.put(body(1), now=1000.0)
    q.put(body(2), now=1001.0)
    # simulate a crash mid-write of a third batch: only the temp file exists
    (q.dir / "00000001002000-1-000009.json.tmp").write_text('{"half":')
    del q
    q2 = DiskQueue(tmp_path)
    items = q2.items()
    assert [i.load()["windows"][0]["bytes_in"] for i in items] == [1, 2]  # FIFO, nothing lost
    assert not list(q2.dir.glob("*.tmp"))  # torn write discarded


def test_queue_caps_at_24h(tmp_path, caplog):
    q = DiskQueue(tmp_path)
    q.put(body(1), now=0.0)
    q.put(body(2), now=3600.0)
    q.put(body(3), now=86_400 + 1800.0)  # first one is now >24 h old
    assert [i.load()["windows"][0]["bytes_in"] for i in q.items()] == [2, 3]
    assert "dropped 1 oldest" in caplog.text


def test_queue_caps_item_count(tmp_path):
    q = DiskQueue(tmp_path, max_items=3)
    for n in range(5):
        q.put(body(n), now=100.0 + n)
    assert [i.load()["windows"][0]["bytes_in"] for i in q.items()] == [2, 3, 4]


# --- sender --------------------------------------------------------------------

def make_sender(tmp_path, clock=None, wan_ip=None) -> Sender:
    return Sender(client=httpx.Client(timeout=5), url=URL, token=TOKEN, queue=DiskQueue(tmp_path),
                  wan_ip=wan_ip, clock=clock or Clock(), rng=random.Random(1))


@respx.mock
def test_send_headers_gzip_and_idempotency(tmp_path):
    route = respx.post(URL).mock(return_value=httpx.Response(200, json={"status": "ok"}))
    s = make_sender(tmp_path)
    s.queue.put(body(1))
    assert s.drain() == 1
    req = route.calls.last.request
    raw = gzip.decompress(req.content)
    assert req.headers["Authorization"] == f"Bearer {TOKEN}"
    assert req.headers["Content-Encoding"] == "gzip"
    assert req.headers["Content-Type"] == "application/json"
    assert req.headers["Idempotency-Key"] == hashlib.sha256(raw).hexdigest()
    sent = json.loads(raw)
    assert list(sent)[:3] == ["sensor_id", "sent_at", "queue_depth"]
    assert sent["queue_depth"] == 0
    assert len(s.queue) == 0


@respx.mock
def test_503_then_200_with_backoff(tmp_path):
    route = respx.post(URL).mock(side_effect=[
        httpx.Response(503, json={"error": "storage_unavailable", "message": "x"}),
        httpx.Response(200, json={"status": "ok"}),
    ])
    clock = Clock()
    s = make_sender(tmp_path, clock)
    s.queue.put(body(1))
    assert s.drain() == 0
    assert len(s.queue) == 1 and s.attempt == 1
    assert 0 <= s.next_attempt_at - clock.t <= 2.0
    first_key = route.calls[0].request.headers["Idempotency-Key"]
    clock.t = s.next_attempt_at - 0.001
    if clock.t > 1_000_000.0:
        assert s.drain() == 0 and route.call_count == 1  # still backing off
    clock.t = s.next_attempt_at
    assert s.drain() == 1
    assert len(s.queue) == 0 and s.attempt == 0
    # the retry sent byte-identical content
    assert route.calls[1].request.headers["Idempotency-Key"] == first_key


@respx.mock
def test_backoff_grows_and_is_capped(tmp_path):
    respx.post(URL).mock(return_value=httpx.Response(503, json={"error": "ingest_disabled"}))
    clock = Clock()
    s = make_sender(tmp_path, clock)
    s.queue.put(body(1))
    for attempt in range(12):
        clock.t = s.next_attempt_at
        s.drain()
        assert s.next_attempt_at - clock.t <= min(300.0, 2.0 * 2 ** attempt)
    assert len(s.queue) == 1  # never dropped on retryable errors


@respx.mock
def test_429_honours_retry_after(tmp_path):
    respx.post(URL).mock(return_value=httpx.Response(429, headers={"Retry-After": "42"},
                                                     json={"error": "rate_limited"}))
    clock = Clock()
    s = make_sender(tmp_path, clock)
    s.queue.put(body(1))
    s.drain()
    assert s.next_attempt_at - clock.t >= 42


@respx.mock
def test_network_error_retries(tmp_path):
    route = respx.post(URL).mock(side_effect=[httpx.ConnectError("boom"),
                                              httpx.Response(200, json={"status": "ok"})])
    clock = Clock()
    s = make_sender(tmp_path, clock)
    s.queue.put(body(1))
    assert s.drain() == 0
    clock.t = s.next_attempt_at
    assert s.drain() == 1 and route.call_count == 2


@respx.mock
def test_lost_response_then_restart_preserves_retry_identity(tmp_path):
    # Model an accepted upload whose response never reaches the sender.
    route = respx.post(URL).mock(side_effect=[
        httpx.ReadTimeout("response lost after acceptance"),
        httpx.Response(200, json={"status": "duplicate"}),
    ])
    clock = Clock()
    sender = make_sender(tmp_path, clock)
    sender.queue.put(body(1), now=clock.t)

    assert sender.drain() == 0
    assert len(sender.queue) == 1
    first_request = route.calls[0].request
    first_raw = gzip.decompress(first_request.content)
    first_key = first_request.headers["Idempotency-Key"]
    sender.client.close()

    # A fresh sender has no memory of the first attempt; only disk survives.
    clock.t += 60
    restarted = make_sender(tmp_path, clock)
    with restarted.client:
        assert len(restarted.queue) == 1
        assert restarted.drain() == 1

    retry_request = route.calls[1].request
    assert gzip.decompress(retry_request.content) == first_raw
    assert retry_request.headers["Idempotency-Key"] == first_key
    assert route.call_count == 2
    assert len(restarted.queue) == 0


@respx.mock
def test_duplicate_is_success(tmp_path):
    respx.post(URL).mock(return_value=httpx.Response(200, json={"status": "duplicate"}))
    s = make_sender(tmp_path)
    s.queue.put(body(1))
    assert s.drain() == 1 and len(s.queue) == 0


@respx.mock
def test_fifo_and_stop_on_failure(tmp_path):
    route = respx.post(URL).mock(side_effect=[httpx.Response(200, json={"status": "ok"}),
                                              httpx.Response(503, json={"error": "x"})])
    s = make_sender(tmp_path)
    for n in (1, 2, 3):
        s.queue.put(body(n), now=1000.0 + n)
    assert s.drain() == 1
    assert route.call_count == 2  # stopped after the failure, third not attempted
    first = json.loads(gzip.decompress(route.calls[0].request.content))
    assert first["windows"][0]["bytes_in"] == 1 and first["queue_depth"] == 2


@respx.mock
@pytest.mark.parametrize("status,code", [(400, "pii_rejected"), (413, "too_large"), (400, "too_many_items")])
def test_permanent_rejection_quarantines(tmp_path, status, code):
    respx.post(URL).mock(return_value=httpx.Response(status, json={"error": code}))
    s = make_sender(tmp_path)
    s.queue.put(body(1))
    s.drain()
    assert len(s.queue) == 0
    assert len(list(s.queue.quarantine_dir.glob("*.json"))) == 1


@respx.mock
def test_401_keeps_batch(tmp_path):
    respx.post(URL).mock(return_value=httpx.Response(401, json={"error": "unauthorized"}))
    s = make_sender(tmp_path)
    s.queue.put(body(1))
    s.drain()
    assert len(s.queue) == 1


@respx.mock
@pytest.mark.parametrize("leak,wan", [("192.168.1.20", None), ("a4:83:e7:12:34:56", None),
                                      ("johns-macbook.local", None),
                                      ("81.2.69.160", "81.2.69.160")])
def test_privacy_guard_blocks_send(tmp_path, caplog, leak, wan):
    route = respx.post(URL).mock(return_value=httpx.Response(200, json={"status": "ok"}))
    s = make_sender(tmp_path, wan_ip=wan)
    b = body(1)
    b["alerts"] = [{"id": "x", "type": "suricata", "device_hash": "dev-aaaaaa", "ts": 1,
                    "severity": "low", "detail": {"signature": f"leak {leak}", "sid": 1, "category": ""}}]
    s.queue.put(b)
    assert s.drain() == 0
    assert route.call_count == 0  # nothing left the box
    assert len(s.queue) == 0 and len(list(s.queue.quarantine_dir.glob("*.json"))) == 1
    assert leak not in caplog.text


@respx.mock
def test_token_never_logged(tmp_path, caplog):
    import logging
    caplog.set_level(logging.DEBUG)
    respx.post(URL).mock(side_effect=[httpx.Response(503, json={"error": "x"}),
                                      httpx.Response(401, json={"error": "unauthorized"})])
    clock = Clock()
    s = make_sender(tmp_path, clock)
    s.queue.put(body(1))
    s.drain()
    clock.t = s.next_attempt_at
    s.drain()
    assert TOKEN not in caplog.text and TOKEN not in repr(s)


@respx.mock
@pytest.mark.parametrize("status", [200, 301, 302, 303, 307, 308, 403])
def test_proxy_login_response_preserves_batch(tmp_path, status):
    respx.post(URL).mock(return_value=httpx.Response(status, text="<html>Sign in</html>"))
    s = make_sender(tmp_path)
    s.queue.put(body(1))
    assert s.drain() == 0
    assert len(s.queue) == 1
    assert not list(s.queue.quarantine_dir.glob("*.json"))
    assert s.next_attempt_at > s.clock()


def test_prolonged_outage_backoff_stays_bounded(tmp_path):
    s = make_sender(tmp_path)
    s.attempt = 10000
    assert 0 <= s.backoff() <= 300
