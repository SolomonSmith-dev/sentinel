"""Roll 10 s host windows up into the 60 s windows of the ingest contract.

- bytes_in, bytes_out, pkts: summed over the six 10 s windows.
- distinct_dests, distinct_ports: max over the 10 s windows. The capture only
  sends exact distinct counts per 10 s window (the lists are capped), so the
  exact 60 s union is not available. max() is a lower bound on the true union
  and equals it when a host talks to the same peers all minute, which is the
  common case. It undercounts slow scans that spread ports across windows; the
  10 s port_scan rule runs before rollup and is not affected.
- syn_ratio: sum(syn_out) / sum(pkts_out) over the bucket, rounded to 4 places.
- score: max of the 10 s scores, or null if no window in the bucket was scored.
- countries: bytes to each destination country, summed. Only outbound `dests`
  carry bytes per remote (inbound_sources has packets only), so this is
  "bytes sent to country" from the per-dest records. Private destinations are
  never looked up and are left out.
- Buckets with pkts == 0 are not shipped: an idle device has nothing to say,
  and every row costs D1 writes.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .geo import GeoDb
from .windows import BUCKET_S, HostWindow


@dataclass
class Bucket:
    device_hash: str
    ts: int
    bytes_in: int = 0
    bytes_out: int = 0
    pkts: int = 0
    pkts_out: int = 0
    syn_out: int = 0
    distinct_dests: int = 0
    distinct_ports: int = 0
    score: float | None = None
    countries: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def add(self, w: HostWindow, score: float | None, geo: GeoDb) -> None:
        self.bytes_in += w.bytes_in
        self.bytes_out += w.bytes_out
        self.pkts += w.pkts
        self.pkts_out += w.pkts_out
        self.syn_out += w.syn_out
        self.distinct_dests = max(self.distinct_dests, w.distinct_dests)
        self.distinct_ports = max(self.distinct_ports, w.distinct_ports_out)
        if score is not None:
            self.score = score if self.score is None else max(self.score, score)
        for d in w.dests:
            cc = geo.lookup(d.ip)
            if cc is not None and d.bytes > 0:
                self.countries[cc] += d.bytes

    def to_json(self) -> dict[str, Any]:
        return {
            "device_hash": self.device_hash,
            "ts": self.ts,
            "duration_s": BUCKET_S,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "pkts": self.pkts,
            "distinct_dests": self.distinct_dests,
            "distinct_ports": self.distinct_ports,
            "syn_ratio": round(self.syn_out / self.pkts_out, 4) if self.pkts_out else 0.0,
            "score": None if self.score is None else round(self.score, 4),
            "countries": dict(sorted(self.countries.items())),
        }


def rollup(items: list[tuple[str, HostWindow, float | None]], geo: GeoDb) -> list[dict[str, Any]]:
    """items: (device_hash, 10 s window, score). Returns contract window dicts."""
    buckets: dict[tuple[str, int], Bucket] = {}
    for device_hash, w, score in items:
        key = (device_hash, w.bucket)
        b = buckets.get(key)
        if b is None:
            b = buckets[key] = Bucket(device_hash=device_hash, ts=w.bucket)
        b.add(w, score, geo)
    return [buckets[k].to_json() for k in sorted(buckets, key=lambda k: (k[1], k[0]))
            if buckets[k].pkts > 0]
