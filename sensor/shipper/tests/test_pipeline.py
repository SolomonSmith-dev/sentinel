from __future__ import annotations

import json

import pytest

from conftest import SALT, T0, window_dict, write_window_file

from sentinel_shipper import privacy
from sentinel_shipper.anonymize import device_hash
from sentinel_shipper.config import ConfigError, Settings
from sentinel_shipper.eve import EveTailer
from sentinel_shipper.model import Scorer
from sentinel_shipper.pipeline import MAX_WINDOWS, Pipeline, build_batches
from sentinel_shipper.queue import DiskQueue
from sentinel_shipper.state import State
from sentinel_shipper.training import Trainer, next_run

MAC = "a4:83:e7:12:34:56"


def make_pipeline(tmp_path, geo, oui, eve=None) -> Pipeline:
    wdir = tmp_path / "windows"
    wdir.mkdir(exist_ok=True)
    return Pipeline(sensor_id="sensor-test", salt=SALT, windows_dir=wdir,
                    state=State(tmp_path / "state" / "state.db"), queue=DiskQueue(tmp_path / "state"),
                    geo=geo, oui=oui, scorer=Scorer(None), eve=eve)


def test_tick_end_to_end(tmp_path, geo, oui):
    p = make_pipeline(tmp_path, geo, oui)
    for i in range(6):
        write_window_file(p.windows_dir, T0 + 10 * i, [window_dict(window_start=T0 + 10 * i)])
    (p.windows_dir / f"{T0 + 60}.ndjson.tmp").write_text("partial")  # in progress: ignored
    res = p.tick(now=T0 + 200)
    assert res.files == 6 and res.windows == 1 and res.batches == 1
    assert sorted(f.name for f in p.windows_dir.iterdir()) == [f"{T0 + 60}.ndjson.tmp"]
    body = p.queue.items()[0].load()
    dh = device_hash(MAC, SALT)
    assert body["devices"] == [{"device_hash": dh, "vendor": "Apple Inc.", "first_seen": T0}]
    (w,) = body["windows"]
    assert w["ts"] == T0 and w["bytes_in"] == 6 * 120394 and w["score"] is None
    assert w["countries"] == {"US": 6 * 60000}
    assert [a["type"] for a in body["alerts"]] == ["new_device"]
    # nothing in the body looks like an address
    raw = json.dumps(body, separators=(",", ":"))
    privacy.check(raw)
    assert MAC not in raw and "192.168" not in raw
    p.state.close()


def test_incomplete_bucket_waits(tmp_path, geo, oui):
    p = make_pipeline(tmp_path, geo, oui)
    write_window_file(p.windows_dir, T0, [window_dict(window_start=T0)])
    write_window_file(p.windows_dir, T0 + 10, [window_dict(window_start=T0 + 10)])
    res = p.tick(now=T0 + 25)  # minute not over yet
    assert res.files == 0 and len(list(p.windows_dir.iterdir())) == 2
    write_window_file(p.windows_dir, T0 + 60, [window_dict(window_start=T0 + 60)])
    res = p.tick(now=T0 + 65)  # capture moved past the bucket: first minute is complete
    assert res.files == 2 and [f.name for f in p.windows_dir.iterdir()] == [f"{T0 + 60}.ndjson"]
    p.state.close()


def test_crash_before_commit_replays(tmp_path, geo, oui, monkeypatch):
    p = make_pipeline(tmp_path, geo, oui)
    write_window_file(p.windows_dir, T0, [window_dict(window_start=T0)])

    def boom(*a, **k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(p.queue, "put", boom)
    with pytest.raises(RuntimeError):
        p.tick(now=T0 + 200)
    assert len(list(p.windows_dir.iterdir())) == 1  # input kept
    assert p.state.get_device(device_hash(MAC, SALT)) is None  # state rolled back
    monkeypatch.undo()
    res = p.tick(now=T0 + 200)
    assert res.files == 1 and res.alerts == 1  # new_device raised on the replay
    p.state.close()


def test_eve_alert_attributed_to_device(tmp_path, geo, oui):
    eve_path = tmp_path / "eve.json"
    eve_path.write_text("")
    tailer = EveTailer(eve_path, tmp_path / "state" / "eve.off", start_at_end=False)
    p = make_pipeline(tmp_path, geo, oui, eve=tailer)
    write_window_file(p.windows_dir, T0, [window_dict(window_start=T0)])
    p.tick(now=T0 + 200)  # learns 192.168.1.20 -> device
    ev = {"timestamp": "2025-10-25T05:39:12.000000+0000", "event_type": "alert",
          "src_ip": "77.88.1.1", "dest_ip": "192.168.1.20",
          "alert": {"signature_id": 2010935, "signature": "ET SCAN Nmap", "category": "Recon", "severity": 1}}
    unknown = dict(ev, dest_ip="192.168.1.99")
    eve_path.write_text(json.dumps(ev) + "\n" + json.dumps(unknown) + "\n")
    res = p.tick(now=T0 + 230)
    assert res.alerts == 1 and res.eve_unattributed == 1
    body = p.queue.items()[-1].load()
    (a,) = body["alerts"]
    assert a["type"] == "suricata" and a["severity"] == "high"
    assert a["device_hash"] == device_hash(MAC, SALT)
    assert a["detail"] == {"signature": "ET SCAN Nmap", "sid": 2010935, "category": "Recon"}
    assert body["devices"] == []  # already listed 30 s earlier (10 min resend rule)
    privacy.check(json.dumps(body))
    p.state.close()


def test_bad_lines_skipped(tmp_path, geo, oui):
    p = make_pipeline(tmp_path, geo, oui)
    path = write_window_file(p.windows_dir, T0, [window_dict(window_start=T0)])
    with path.open("a") as fh:
        fh.write("{not json\n")
    res = p.tick(now=T0 + 200)
    assert res.host_windows == 1
    p.state.close()


def test_build_batches_respects_limits():
    windows = [{"device_hash": f"dev-{i % 300:06x}", "ts": 60 * i} for i in range(1200)]
    alerts = [{"device_hash": "dev-000001", "id": str(i)} for i in range(10)]
    devices = {w["device_hash"]: {"device_hash": w["device_hash"]} for w in windows}
    batches = build_batches("s", windows, alerts, devices)
    assert sum(len(b["windows"]) for b in batches) == 1200
    assert sum(len(b["alerts"]) for b in batches) == 10
    for b in batches:
        assert len(b["windows"]) <= MAX_WINDOWS and len(b["alerts"]) <= 500 and len(b["devices"]) <= 200
        refs = {x["device_hash"] for x in b["windows"] + b["alerts"]}
        assert refs == {d["device_hash"] for d in b["devices"]}


# --- config --------------------------------------------------------------------

def test_config_refuses_without_token_or_salt():
    with pytest.raises(ConfigError, match="SENTINEL_TOKEN"):
        Settings.from_env({"SENTINEL_SALT": "x"})
    with pytest.raises(ConfigError, match="SENTINEL_SALT"):
        Settings.from_env({"SENTINEL_TOKEN": "x", "SENTINEL_SALT": "  "})


def test_config_defaults_and_repr_hide_secrets():
    s = Settings.from_env({"SENTINEL_TOKEN": "tok-fake-123", "SENTINEL_SALT": "salt-fake-456",
                           "SENTINEL_WAN_IP": "81.2.69.160", "SENTINEL_API": "https://x.test/"})
    assert s.ingest_url == "https://x.test/api/ingest"
    assert str(s.windows_dir) == "/var/lib/sentinel/windows"
    assert str(s.state_dir) == "/var/lib/sentinel/state"
    assert str(s.eve_path) == "/var/log/suricata/eve.json"
    r = repr(s)
    assert "tok-fake-123" not in r and "salt-fake-456" not in r and "81.2.69.160" not in r


def test_config_loads_mounted_credentials(tmp_path):
    token, salt = tmp_path / "token", tmp_path / "salt"
    token.write_text("test-mounted-token\n")
    salt.write_text("test-mounted-salt\n")
    s = Settings.from_env({"SENTINEL_TOKEN_FILE": str(token), "SENTINEL_SALT_FILE": str(salt)})
    assert s.token == "test-mounted-token" and s.salt == "test-mounted-salt"
    assert s.token not in repr(s) and s.salt not in repr(s)


def test_config_rejects_ambiguous_credentials(tmp_path):
    with pytest.raises(ConfigError, match="set only one"):
        Settings.from_env({"SENTINEL_TOKEN": "test-token", "SENTINEL_TOKEN_FILE": str(tmp_path / "token")})


@pytest.mark.parametrize("content", [None, "  ", b"\xff"])
def test_config_rejects_unusable_credential_file(tmp_path, content):
    token = tmp_path / "token"
    if isinstance(content, bytes):
        token.write_bytes(content)
    elif content is not None:
        token.write_text(content)
    with pytest.raises(ConfigError, match="SENTINEL_TOKEN"):
        Settings.from_env({"SENTINEL_TOKEN_FILE": str(token), "SENTINEL_SALT": "test-salt"})


def test_main_exits_without_config(monkeypatch, capsys):
    from sentinel_shipper.main import main
    monkeypatch.delenv("SENTINEL_TOKEN", raising=False)
    monkeypatch.delenv("SENTINEL_SALT", raising=False)
    assert main([]) == 2
    assert "refusing to start" in capsys.readouterr().err


# --- training schedule -----------------------------------------------------------

def test_next_run():
    from datetime import datetime
    assert next_run(datetime(2026, 1, 1, 1, 0), 3, 30) == datetime(2026, 1, 1, 3, 30)
    assert next_run(datetime(2026, 1, 1, 3, 30), 3, 30) == datetime(2026, 1, 2, 3, 30)


def test_bootstrap_training_needs_two_hours(tmp_path):
    from test_model import benign
    st = State(tmp_path / "s.db")
    scorer = Scorer(None)
    tr = Trainer(st, scorer, tmp_path / "model.joblib")
    rows = benign(1500)
    st.add_features((T0 + i * 4, "dev-aaaaaa", r) for i, r in enumerate(rows[:1000]))  # 4000 s span
    assert tr.maybe_train(now=T0 + 4000) is False and scorer.model is None
    st.add_features((T0 + 7200 + i, "dev-aaaaaa", r) for i, r in enumerate(rows[1000:]))
    tr._next_bootstrap = 0.0
    assert tr.maybe_train(now=T0 + 8000) is True
    assert scorer.model is not None and (tmp_path / "model.joblib").exists()
    st.close()


def test_devices_listed_when_new_or_every_10_minutes(tmp_path, geo, oui):
    p = make_pipeline(tmp_path, geo, oui)
    dh = device_hash(MAC, SALT)

    def run(start: int, now: int) -> dict:
        write_window_file(p.windows_dir, start, [window_dict(window_start=start)])
        p.tick(now=now)
        return p.queue.items()[-1].load()

    assert [d["device_hash"] for d in run(T0, T0 + 100)["devices"]] == [dh]   # new
    assert run(T0 + 60, T0 + 200)["devices"] == []                          # sent 100 s ago
    assert run(T0 + 120, T0 + 700)["devices"] == []                         # exactly 600 s: not yet
    assert [d["device_hash"] for d in run(T0 + 180, T0 + 701)["devices"]] == [dh]  # > 10 min
    # the timestamp is persisted: a restarted shipper does not resend early
    p.state.close()
    p2 = make_pipeline(tmp_path, geo, oui)
    p = p2
    assert run(T0 + 240, T0 + 800)["devices"] == []
    p2.state.close()


def test_idle_device_window_not_shipped(tmp_path, geo, oui):
    p = make_pipeline(tmp_path, geo, oui)
    idle = window_dict(host={"mac": "b8:27:eb:00:00:01", "ip": "192.168.1.40"}, pkts_in=0, pkts_out=0,
                       bytes_in=0, bytes_out=0, syn_out=0, synack_in=0, distinct_dests=0,
                       distinct_ports_out=0, dests=[], inbound_sources=[])
    write_window_file(p.windows_dir, T0, [window_dict(), idle])
    p.tick(now=T0 + 200)
    body = p.queue.items()[0].load()
    idle_dh = device_hash("b8:27:eb:00:00:01", SALT)
    assert [w["device_hash"] for w in body["windows"]] == [device_hash(MAC, SALT)]
    assert all(w["pkts"] > 0 for w in body["windows"])
    # its new_device alert still ships, so it is listed
    assert idle_dh in {a["device_hash"] for a in body["alerts"]}
    p.state.close()


@pytest.mark.parametrize("endpoint", [
    "http://example.com", "http://127.0.0.1:8080", "http://[::1]:8080",
    "https://", "https://example.com:bad", "https://user:password@example.com",
    "https://example.com?token=x", "https://example.com#fragment", "https://[broken",
])
def test_config_rejects_insecure_or_ambiguous_endpoint(endpoint):
    with pytest.raises(ConfigError, match="HTTPS"):
        Settings.from_env({"SENTINEL_TOKEN": "fake", "SENTINEL_SALT": "fake", "SENTINEL_API": endpoint})
