from __future__ import annotations

import json
import os

from conftest import T0, make_window

from sentinel_shipper.eve import EveTailer, parse_event
from sentinel_shipper.rollup import rollup


# --- rollup --------------------------------------------------------------------

def test_rollup_math(geo):
    w1 = make_window(window_start=T0, bytes_in=100, bytes_out=10, pkts_in=5, pkts_out=20, syn_out=2,
                     distinct_dests=3, distinct_ports_out=4,
                     dests=[{"ip": "8.8.8.8", "pkts": 1, "bytes": 1000, "syn": 0, "ports": [53]},
                            {"ip": "77.88.1.1", "pkts": 1, "bytes": 50, "syn": 0, "ports": [443]},
                            {"ip": "192.168.1.1", "pkts": 1, "bytes": 999, "syn": 0, "ports": [53]}])
    w2 = make_window(window_start=T0 + 50, bytes_in=200, bytes_out=20, pkts_in=5, pkts_out=30, syn_out=3,
                     distinct_dests=7, distinct_ports_out=2,
                     dests=[{"ip": "8.8.4.4", "pkts": 1, "bytes": 5, "syn": 0, "ports": [53]},
                            {"ip": "8.8.8.8", "pkts": 1, "bytes": 500, "syn": 0, "ports": [53]}])
    w3 = make_window(window_start=T0 + 60, bytes_in=1, bytes_out=1, pkts_in=1, pkts_out=1, syn_out=0,
                     distinct_dests=1, distinct_ports_out=1, dests=[])
    out = rollup([("dev-aaaaaa", w1, 0.2), ("dev-aaaaaa", w2, 0.6), ("dev-aaaaaa", w3, None)], geo)
    assert len(out) == 2
    first, second = out
    assert first == {
        "device_hash": "dev-aaaaaa", "ts": T0, "duration_s": 60,
        "bytes_in": 300, "bytes_out": 30, "pkts": 60,
        "distinct_dests": 7,   # max of windows, not sum
        "distinct_ports": 4,
        "syn_ratio": 0.1,      # (2+3)/(20+30)
        "score": 0.6,          # max
        "countries": {"??": 5, "RU": 50, "US": 1500},  # private 192.168.1.1 left out
    }
    assert second["ts"] == T0 + 60 and second["score"] is None and second["countries"] == {}
    assert all(w["ts"] % 60 == 0 for w in out)


def test_rollup_separates_devices(geo):
    out = rollup([("dev-aaaaaa", make_window(), None), ("dev-bbbbbb", make_window(), None)], geo)
    assert {w["device_hash"] for w in out} == {"dev-aaaaaa", "dev-bbbbbb"}


def test_rollup_zero_pkts_out(geo):
    out = rollup([("dev-aaaaaa", make_window(pkts_out=0, syn_out=0), None)], geo)
    assert out[0]["syn_ratio"] == 0.0


# --- eve -----------------------------------------------------------------------

def eve_line(sev=1, src="77.88.1.1", dst="192.168.1.20", sid=2010935, event_type="alert",
             sig="ET SCAN Possible Nmap User-Agent Observed") -> str:
    return json.dumps({
        "timestamp": "2025-10-25T05:39:12.123456+0000", "event_type": event_type,
        "src_ip": src, "src_port": 4444, "dest_ip": dst, "dest_port": 80, "proto": "TCP",
        "alert": {"action": "allowed", "signature_id": sid, "rev": 3, "signature": sig,
                  "category": "Web Application Attack", "severity": sev},
    }) + "\n"


def test_parse_event_maps_severity_and_local_side():
    ev = parse_event(eve_line(sev=1))
    assert ev and ev.severity == "high" and ev.local_ip == "192.168.1.20" and ev.sid == 2010935
    assert parse_event(eve_line(sev=2)).severity == "medium"
    assert parse_event(eve_line(sev=3)).severity == "low"
    out = parse_event(eve_line(src="192.168.1.30", dst="8.8.8.8"))
    assert out.local_ip == "192.168.1.30"
    assert ev.ts == 1761370752
    assert set(ev.detail()) == {"signature", "sid", "category"}


def test_parse_event_ignores_non_alerts_and_public_only():
    assert parse_event(eve_line(event_type="flow")) is None
    assert parse_event(eve_line(src="8.8.8.8", dst="1.0.0.1")) is None
    assert parse_event("not json") is None


def test_parse_event_redacts_addresses_in_signature():
    ev = parse_event(eve_line(sig="ET POLICY traffic to 10.9.8.7 from aa:bb:cc:dd:ee:ff"))
    assert "10.9.8.7" not in ev.signature and "aa:bb" not in ev.signature


def test_tailer_reads_incrementally_and_resumes(tmp_path):
    eve, st = tmp_path / "eve.json", tmp_path / "state" / "eve.json.offset"
    eve.write_text(eve_line(sid=1))
    t = EveTailer(eve, st, start_at_end=False)
    assert [e.sid for e in t.read()] == [1]
    t.commit()
    with eve.open("a") as fh:
        fh.write(eve_line(sid=2))
        fh.write(eve_line(sid=3)[:40])  # half-written line: must wait
    t2 = EveTailer(eve, st, start_at_end=False)  # fresh process, offset from disk
    assert [e.sid for e in t2.read()] == [2]
    t2.commit()
    with eve.open("a") as fh:
        fh.write(eve_line(sid=3)[40:])
    assert [e.sid for e in t2.read()] == [3]


def test_tailer_uncommitted_read_is_replayed(tmp_path):
    eve, st = tmp_path / "eve.json", tmp_path / "off.json"
    eve.write_text(eve_line(sid=1))
    t = EveTailer(eve, st, start_at_end=False)
    t.read()
    t.commit()
    with eve.open("a") as fh:
        fh.write(eve_line(sid=2))
    assert [e.sid for e in t.read()] == [2]
    # crash before commit: next process sees sid 2 again
    assert [e.sid for e in EveTailer(eve, st).read()] == [2]


def test_tailer_handles_rotation(tmp_path):
    eve, st = tmp_path / "eve.json", tmp_path / "off.json"
    eve.write_text(eve_line(sid=1) + eve_line(sid=2))
    t = EveTailer(eve, st, start_at_end=False)
    t.read()
    t.commit()
    os.rename(eve, tmp_path / "eve.json.1")  # logrotate: move, then create new file
    eve.write_text(eve_line(sid=10) + eve_line(sid=11) + eve_line(sid=12))  # new inode, longer
    assert [e.sid for e in t.read()] == [10, 11, 12]


def test_tailer_handles_truncation(tmp_path):
    eve, st = tmp_path / "eve.json", tmp_path / "off.json"
    eve.write_text(eve_line(sid=1) + eve_line(sid=2))
    t = EveTailer(eve, st, start_at_end=False)
    t.read()
    t.commit()
    with eve.open("w") as fh:  # copytruncate: same inode, shorter
        fh.write(eve_line(sid=20))
    assert [e.sid for e in t.read()] == [20]


def test_tailer_first_run_starts_at_end(tmp_path):
    eve, st = tmp_path / "eve.json", tmp_path / "off.json"
    eve.write_text(eve_line(sid=1))
    t = EveTailer(eve, st)  # default: do not replay history
    assert t.read() == []
    t.commit()
    with eve.open("a") as fh:
        fh.write(eve_line(sid=2))
    assert [e.sid for e in t.read()] == [2]


def test_tailer_missing_file(tmp_path):
    assert EveTailer(tmp_path / "nope.json", tmp_path / "off.json").read() == []


def test_rollup_drops_idle_buckets(geo):
    idle = make_window(pkts_in=0, pkts_out=0, bytes_in=0, bytes_out=0, syn_out=0, dests=[])
    busy = make_window(window_start=T0 + 60)
    out = rollup([("dev-aaaaaa", idle, 0.4), ("dev-aaaaaa", busy, None)], geo)
    assert [w["ts"] for w in out] == [T0 + 60]
