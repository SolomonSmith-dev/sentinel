"""One shipper tick: windows + eve -> rules, scores, rollup -> durable batches.

Order of commits, chosen so a crash at any point replays work instead of
losing it:
  1. build batches in memory (sqlite changes are inside an open transaction)
  2. put every batch in the durable queue (fsynced)
  3. commit sqlite, delete the processed .ndjson files, commit the eve offset
A replay re-sends the same windows (upserted by device_hash, ts) and the same
alerts (deterministic ids), so it is harmless.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import anonymize
from .eve import EveTailer, to_alerts
from .geo import GeoDb, is_public
from .mlcore import Scorer, raw_features
from .queue import DiskQueue
from .rollup import rollup
from .rules import Alert, RuleEngine
from .state import State
from .windows import BUCKET_S, complete_buckets, file_window_start, list_finished, read_window_file

log = logging.getLogger(__name__)

MAX_WINDOWS = 500
MAX_ALERTS = 500
MAX_DEVICES = 200
MAX_FILES_PER_TICK = 360  # one hour of 10 s windows


@dataclass
class TickResult:
    files: int = 0
    host_windows: int = 0
    windows: int = 0
    alerts: int = 0
    batches: int = 0
    eve_unattributed: int = 0


def build_batches(sensor_id: str, windows: list[dict[str, Any]], alerts: list[dict[str, Any]],
                  devices: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Split into contract-sized batches.

    `devices` holds only the devices due for (re)sending; a batch lists the due
    devices it references. Others are known to the API already and are left
    out to save D1 writes.
    """
    batches: list[dict[str, Any]] = []
    cur_w: list[dict[str, Any]] = []
    cur_a: list[dict[str, Any]] = []
    cur_d: set[str] = set()

    def flush() -> None:
        nonlocal cur_w, cur_a, cur_d
        if cur_w or cur_a:
            batches.append({
                "sensor_id": sensor_id,
                "devices": [devices[d] for d in sorted(cur_d) if d in devices],
                "windows": cur_w,
                "alerts": cur_a,
            })
        cur_w, cur_a, cur_d = [], [], set()

    for kind, item in [("w", w) for w in windows] + [("a", a) for a in alerts]:
        dh = item["device_hash"]
        new_dev = dh not in cur_d
        listed = sum(1 for d in cur_d if d in devices)
        if (kind == "w" and len(cur_w) >= MAX_WINDOWS) or (kind == "a" and len(cur_a) >= MAX_ALERTS) \
                or (new_dev and dh in devices and listed >= MAX_DEVICES):
            flush()
        (cur_w if kind == "w" else cur_a).append(item)
        cur_d.add(dh)
    flush()
    return batches


@dataclass
class Pipeline:
    sensor_id: str
    salt: str = field(repr=False)
    windows_dir: Path
    state: State
    queue: DiskQueue
    geo: GeoDb
    oui: anonymize.OuiDb
    scorer: Scorer
    eve: EveTailer | None = None

    def __post_init__(self) -> None:
        self.rules = RuleEngine(self.state, self.geo, self.sensor_id)

    def tick(self, now: float | None = None) -> TickResult:
        now = time.time() if now is None else now
        res = TickResult()
        ready = complete_buckets(list_finished(self.windows_dir), now)
        files = ready[:MAX_FILES_PER_TICK]
        if len(ready) > MAX_FILES_PER_TICK:
            # never split a 60 s bucket across ticks: leave the cut bucket for next time
            start = file_window_start(files[-1])
            if start is not None:
                cut = start - start % BUCKET_S
                kept = [f for f in files if (file_window_start(f) or 0) < cut]
                files = kept or files
        self.state.begin()
        try:
            alerts: list[Alert] = []
            devices: dict[str, dict[str, Any]] = {}
            scored: list[tuple[str, Any, float | None]] = []
            for path in files:
                host_windows = read_window_file(path)
                res.files += 1
                if not host_windows:
                    continue
                dhs = [anonymize.device_hash(w.mac, self.salt) for w in host_windows]
                feats = [raw_features(w) for w in host_windows]
                scores = self.scorer.score(feats)
                for w, dh, vec, score in zip(host_windows, dhs, feats, scores):
                    vendor = self.oui.vendor(w.mac)
                    is_new = self.state.upsert_device(dh, vendor, w.window_start)
                    dev = self.state.get_device(dh)
                    assert dev is not None
                    devices[dh] = {"device_hash": dh, "vendor": dev.vendor, "first_seen": dev.first_seen}
                    if w.ip and not is_public(w.ip):
                        self.state.map_ip(w.ip, dh, w.window_start)
                    alerts.extend(self.rules.evaluate(w, dh, is_new, dev.first_seen, score))
                    scored.append((dh, w, score))
                    res.host_windows += 1
                self.state.add_features((w.window_start, dh, vec)
                                        for w, dh, vec in zip(host_windows, dhs, feats))

            if self.eve is not None:
                pairs, dropped = to_alerts(self.eve.read(), self.state.device_for_ip)
                res.eve_unattributed = dropped
                if dropped:
                    log.info("eve: %d alert(s) for unknown local hosts skipped", dropped)
                for dh, ev in pairs:
                    a = self.rules.suricata(dh, ev.ts, ev.severity, ev.detail())
                    if a:
                        alerts.append(a)
                        dev = self.state.get_device(dh)
                        if dev:
                            devices[dh] = {"device_hash": dh, "vendor": dev.vendor,
                                           "first_seen": dev.first_seen}

            windows = rollup(scored, self.geo)
            alert_json = [a.to_json() for a in sorted(alerts, key=lambda a: (a.ts, a.type))]
            # Device rows only when new to the API or not sent for 10 minutes.
            due = {dh: d for dh, d in devices.items() if self.state.device_due(dh, int(now))}
            batches = build_batches(self.sensor_id, windows, alert_json, due)
            for b in batches:
                self.queue.put(b, now)
            self.state.mark_included((d["device_hash"] for b in batches for d in b["devices"]), int(now))
            self.state.prune(int(now))
            self.state.commit()
        except BaseException:
            self.state.rollback()
            raise
        # batches are durable and state committed: now safe to forget the inputs
        for path in files:
            path.unlink(missing_ok=True)
        if self.eve is not None:
            self.eve.commit()
        res.windows, res.alerts, res.batches = len(windows), len(alert_json), len(batches)
        return res
