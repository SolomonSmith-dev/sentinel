"""Local sqlite state in the state dir: devices, per-device country history,
alert debounce, the local IP -> device map (for Suricata attribution) and the
rolling ML feature store.

Writes happen inside one transaction per tick and are committed only after the
tick's batches are durably queued, so a crash replays the tick instead of
losing or half-applying it.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

SEVEN_DAYS = 7 * 86400

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_hash TEXT PRIMARY KEY,
    vendor TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS device_countries (
    device_hash TEXT NOT NULL,
    country TEXT NOT NULL,
    last_seen INTEGER NOT NULL,
    PRIMARY KEY (device_hash, country)
);
CREATE TABLE IF NOT EXISTS debounce (
    key TEXT PRIMARY KEY,
    last_ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ip_map (
    ip TEXT PRIMARY KEY,
    device_hash TEXT NOT NULL,
    last_seen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS features (
    ts INTEGER NOT NULL,
    device_hash TEXT NOT NULL,
    bytes_in REAL NOT NULL,
    bytes_out REAL NOT NULL,
    pkts REAL NOT NULL,
    distinct_dests REAL NOT NULL,
    distinct_ports REAL NOT NULL,
    syn_ratio REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS features_ts ON features (ts);
CREATE TABLE IF NOT EXISTS device_shipped (
    device_hash TEXT PRIMARY KEY,
    last_included INTEGER NOT NULL
);
"""

DEVICE_RESEND_S = 600


@dataclass(frozen=True)
class Device:
    device_hash: str
    vendor: str
    first_seen: int
    last_seen: int


class State:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        # isolation_level=None + explicit BEGIN gives us one transaction per tick.
        self.db = sqlite3.connect(str(path), isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(SCHEMA)

    # transactions -----------------------------------------------------------
    def begin(self) -> None:
        if not self.db.in_transaction:
            self.db.execute("BEGIN")

    def commit(self) -> None:
        if self.db.in_transaction:
            self.db.execute("COMMIT")

    def rollback(self) -> None:
        if self.db.in_transaction:
            self.db.execute("ROLLBACK")

    def close(self) -> None:
        self.rollback()
        self.db.close()

    # devices ----------------------------------------------------------------
    def get_device(self, device_hash: str) -> Device | None:
        row = self.db.execute(
            "SELECT device_hash, vendor, first_seen, last_seen FROM devices WHERE device_hash=?",
            (device_hash,),
        ).fetchone()
        return Device(*row) if row else None

    def upsert_device(self, device_hash: str, vendor: str, ts: int) -> bool:
        """Record a sighting. Returns True if the device was new."""
        existing = self.get_device(device_hash)
        if existing is None:
            self.db.execute(
                "INSERT INTO devices (device_hash, vendor, first_seen, last_seen) VALUES (?,?,?,?)",
                (device_hash, vendor, ts, ts),
            )
            return True
        self.db.execute(
            "UPDATE devices SET last_seen=MAX(last_seen, ?), first_seen=MIN(first_seen, ?) "
            "WHERE device_hash=?",
            (ts, ts, device_hash),
        )
        return False

    # geo history ------------------------------------------------------------
    def countries_seen(self, device_hash: str, since: int) -> set[str]:
        rows = self.db.execute(
            "SELECT country FROM device_countries WHERE device_hash=? AND last_seen>=?",
            (device_hash, since),
        )
        return {r[0] for r in rows}

    def mark_country(self, device_hash: str, country: str, ts: int) -> None:
        self.db.execute(
            "INSERT INTO device_countries (device_hash, country, last_seen) VALUES (?,?,?) "
            "ON CONFLICT(device_hash, country) DO UPDATE SET last_seen=MAX(last_seen, excluded.last_seen)",
            (device_hash, country, ts),
        )

    # debounce ---------------------------------------------------------------
    def debounce_last(self, key: str) -> int | None:
        row = self.db.execute("SELECT last_ts FROM debounce WHERE key=?", (key,)).fetchone()
        return int(row[0]) if row else None

    def debounce_set(self, key: str, ts: int) -> None:
        self.db.execute(
            "INSERT INTO debounce (key, last_ts) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET last_ts=excluded.last_ts",
            (key, ts),
        )

    # device list in batches ---------------------------------------------------
    def device_due(self, device_hash: str, now: int, resend_s: int = DEVICE_RESEND_S) -> bool:
        """True if the device was never put in a batch's `devices` or not for resend_s seconds."""
        row = self.db.execute("SELECT last_included FROM device_shipped WHERE device_hash=?",
                              (device_hash,)).fetchone()
        return row is None or now - int(row[0]) > resend_s

    def mark_included(self, device_hashes: Iterable[str], now: int) -> None:
        self.db.executemany(
            "INSERT INTO device_shipped (device_hash, last_included) VALUES (?,?) "
            "ON CONFLICT(device_hash) DO UPDATE SET last_included=excluded.last_included",
            ((dh, now) for dh in device_hashes),
        )

    # ip map -----------------------------------------------------------------
    def map_ip(self, ip: str, device_hash: str, ts: int) -> None:
        self.db.execute(
            "INSERT INTO ip_map (ip, device_hash, last_seen) VALUES (?,?,?) "
            "ON CONFLICT(ip) DO UPDATE SET device_hash=excluded.device_hash, last_seen=excluded.last_seen "
            "WHERE excluded.last_seen >= ip_map.last_seen",
            (ip, device_hash, ts),
        )

    def device_for_ip(self, ip: str) -> str | None:
        row = self.db.execute("SELECT device_hash FROM ip_map WHERE ip=?", (ip,)).fetchone()
        return row[0] if row else None

    # features ---------------------------------------------------------------
    def add_features(self, rows: Iterable[tuple[int, str, Sequence[float]]]) -> None:
        self.db.executemany(
            "INSERT INTO features (ts, device_hash, bytes_in, bytes_out, pkts, distinct_dests, "
            "distinct_ports, syn_ratio) VALUES (?,?,?,?,?,?,?,?)",
            ((ts, dh, *[float(v) for v in vec]) for ts, dh, vec in rows),
        )

    def feature_span_s(self) -> int:
        row = self.db.execute("SELECT MIN(ts), MAX(ts) FROM features").fetchone()
        if not row or row[0] is None:
            return 0
        return int(row[1]) - int(row[0])

    def feature_rows(self, since: int, limit: int) -> list[tuple[float, ...]]:
        """A uniform random sample of feature rows newer than `since`."""
        return self.db.execute(
            "SELECT bytes_in, bytes_out, pkts, distinct_dests, distinct_ports, syn_ratio "
            "FROM features WHERE ts>=? ORDER BY RANDOM() LIMIT ?",
            (since, limit),
        ).fetchall()

    def prune(self, now: int) -> None:
        cutoff = now - SEVEN_DAYS
        self.db.execute("DELETE FROM features WHERE ts<?", (cutoff,))
        self.db.execute("DELETE FROM device_countries WHERE last_seen<?", (cutoff,))
        self.db.execute("DELETE FROM debounce WHERE last_ts<?", (cutoff,))
        self.db.execute("DELETE FROM ip_map WHERE last_seen<?", (cutoff,))
