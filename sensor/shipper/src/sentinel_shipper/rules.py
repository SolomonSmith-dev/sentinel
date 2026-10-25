"""Deterministic detection rules on each 10 s host window.

Thresholds (per 10 s window):
- flood (critical): >20 000 pkts to one destination (2 000 pkts/s), or >500
  SYN-without-ACK from one inbound source, or >500 outbound SYNs (syn_out).
- port_scan (high): >20 distinct destination ports, either the host itself
  (distinct_ports_out) or one inbound source (inbound_sources[].distinct_ports).
- new_device (low): hashed MAC not in local device state.
- geo_anomaly (medium): outbound to a country this device has not used in the
  trailing 7 days; suppressed during the device's first 24 h of history so the
  first day does not alert on every country.
- ml_anomaly (high): calibrated isolation-forest score > 0.8.

Debounce: an alert of the same type for the same device fires at most once per
5 minutes (window time, not wall time). Suricata alerts debounce per signature.
Alert details carry counts and country codes only, never addresses.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from .geo import GeoDb, UNKNOWN as GEO_UNKNOWN
from .mlcore import ALERT_THRESHOLD
from .state import SEVEN_DAYS, State
from .windows import HostWindow

FLOOD_DEST_PKTS = 20_000
FLOOD_SYN = 500
SCAN_PORTS = 20
DEBOUNCE_S = 300
GEO_WARMUP_S = 86_400

SEVERITY = {
    "flood": "critical",
    "port_scan": "high",
    "geo_anomaly": "medium",
    "new_device": "low",
    "ml_anomaly": "high",
}

_ALERT_NS = uuid.UUID("5d1b6c1e-6a52-4c58-9f3e-8a1e3b0c7d21")


def alert_id(sensor_id: str, kind: str, device_hash: str, ts: int, discriminator: str = "") -> str:
    """Deterministic id, so a replayed tick upserts the same alert instead of duplicating it."""
    return str(uuid.uuid5(_ALERT_NS, f"{sensor_id}|{kind}|{device_hash}|{ts}|{discriminator}"))


@dataclass
class Alert:
    type: str
    device_hash: str
    ts: int
    severity: str
    detail: dict[str, Any]
    id: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "device_hash": self.device_hash,
            "ts": self.ts,
            "severity": self.severity,
            "detail": self.detail,
        }


@dataclass
class RuleEngine:
    state: State
    geo: GeoDb
    sensor_id: str
    debounce_s: int = DEBOUNCE_S
    _pending: list[Alert] = field(default_factory=list)

    def _emit(self, kind: str, device_hash: str, ts: int, detail: dict[str, Any],
              debounce_key: str | None = None, severity: str | None = None) -> Alert | None:
        key = debounce_key or f"{kind}|{device_hash}"
        last = self.state.debounce_last(key)
        if last is not None and 0 <= ts - last < self.debounce_s:
            return None
        self.state.debounce_set(key, ts)
        alert = Alert(
            type=kind,
            device_hash=device_hash,
            ts=ts,
            severity=severity or SEVERITY[kind],
            detail=detail,
            id=alert_id(self.sensor_id, kind, device_hash, ts, key),
        )
        return alert

    def evaluate(self, w: HostWindow, device_hash: str, is_new: bool, first_seen: int,
                 score: float | None) -> list[Alert]:
        """All alerts for one host window. Updates country history as a side effect."""
        ts = w.window_start
        candidates: list[tuple[str, dict[str, Any]]] = []

        if is_new:
            candidates.append(("new_device", {"window_s": w.window_s}))

        flood = self._flood(w)
        if flood:
            candidates.append(("flood", flood))

        scan = self._scan(w)
        if scan:
            candidates.append(("port_scan", scan))

        geo = self._geo(w, device_hash, first_seen)
        if geo:
            candidates.append(("geo_anomaly", geo))

        if score is not None and score > ALERT_THRESHOLD:
            candidates.append(("ml_anomaly", {
                "score": round(score, 3),
                "window_s": w.window_s,
                "pkts": w.pkts,
                "distinct_ports": w.distinct_ports_out,
                "distinct_dests": w.distinct_dests,
            }))

        alerts: list[Alert] = []
        for kind, detail in candidates:
            alert = self._emit(kind, device_hash, ts, detail)
            if alert:
                alerts.append(alert)
        return alerts

    def suricata(self, device_hash: str, ts: int, severity: str, detail: dict[str, Any]) -> Alert | None:
        sid = detail.get("sid", "")
        return self._emit("suricata", device_hash, ts, detail,
                          debounce_key=f"suricata|{device_hash}|{sid}", severity=severity)

    # individual rules -------------------------------------------------------
    def _flood(self, w: HostWindow) -> dict[str, Any] | None:
        top_dest = max(w.dests, key=lambda d: d.pkts, default=None)
        if top_dest is not None and top_dest.pkts > FLOOD_DEST_PKTS:
            detail: dict[str, Any] = {"direction": "outbound", "kind": "pkts_to_one_dest",
                                      "pkts": top_dest.pkts, "window_s": w.window_s}
            cc = self.geo.lookup(top_dest.ip)
            if cc:
                detail["country"] = cc
            return detail
        top_syn_src = max(w.inbound_sources, key=lambda s: s.syn, default=None)
        if top_syn_src is not None and top_syn_src.syn > FLOOD_SYN:
            detail = {"direction": "inbound", "kind": "syn_from_one_source",
                      "syn": top_syn_src.syn, "window_s": w.window_s}
            cc = self.geo.lookup(top_syn_src.ip)
            if cc:
                detail["country"] = cc
            return detail
        if w.syn_out > FLOOD_SYN:
            return {"direction": "outbound", "kind": "syn_out", "syn": w.syn_out,
                    "synack_in": w.synack_in, "window_s": w.window_s}
        return None

    def _scan(self, w: HostWindow) -> dict[str, Any] | None:
        if w.distinct_ports_out > SCAN_PORTS:
            return {"direction": "outbound", "distinct_ports": w.distinct_ports_out,
                    "distinct_dests": w.distinct_dests, "window_s": w.window_s}
        top = max(w.inbound_sources, key=lambda s: s.distinct_ports, default=None)
        if top is not None and top.distinct_ports > SCAN_PORTS:
            detail: dict[str, Any] = {"direction": "inbound", "distinct_ports": top.distinct_ports,
                                      "window_s": w.window_s}
            cc = self.geo.lookup(top.ip)
            if cc:
                detail["country"] = cc
            return detail
        return None

    def _geo(self, w: HostWindow, device_hash: str, first_seen: int) -> dict[str, Any] | None:
        ts = w.window_start
        current = {cc for d in w.dests if (cc := self.geo.lookup(d.ip)) and cc != GEO_UNKNOWN}
        if not current:
            return None
        known = self.state.countries_seen(device_hash, ts - SEVEN_DAYS)
        new = sorted(current - known)
        for cc in current:
            self.state.mark_country(device_hash, cc, ts)
        if not new or ts - first_seen < GEO_WARMUP_S:
            return None
        return {"country": new[0], "new_countries": len(new)}
