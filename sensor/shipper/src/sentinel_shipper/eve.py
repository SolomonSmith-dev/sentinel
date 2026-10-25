"""Tail Suricata's eve.json and turn `alert` events into `suricata` alerts.

The offset (plus the file's inode) lives in the state dir. Rotation (new inode)
or truncation (file shorter than our offset) restarts from byte 0 of the new
file. Only complete lines are consumed; a half-written last line waits for the
next tick. The new offset is committed only after the batch carrying these
alerts is durably queued.

From each event we keep signature, sid and category (address-looking text
redacted), the timestamp, the severity and the local side's address, which is
resolved to a device hash and then dropped. Nothing else from eve is shipped.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from .geo import is_public
from .privacy import redact

log = logging.getLogger(__name__)

MAX_READ_BYTES = 8 * 1024 * 1024  # per tick, so a burst cannot stall the loop

SEVERITY_MAP = {1: "high", 2: "medium", 3: "low"}


@dataclass(frozen=True)
class EveAlert:
    ts: int
    local_ip: str  # never shipped; resolved to a device hash by the caller
    severity: str
    signature: str
    sid: int
    category: str

    def detail(self) -> dict[str, object]:
        return {"signature": self.signature, "sid": self.sid, "category": self.category}


@dataclass(frozen=True)
class Position:
    inode: int
    offset: int


def parse_ts(value: str) -> int:
    # Suricata: 2025-10-25T05:39:12.123456+0000
    return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp())


def parse_event(line: str) -> EveAlert | None:
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(ev, dict) or ev.get("event_type") != "alert":
        return None
    alert = ev.get("alert") or {}
    if not isinstance(alert, dict):
        return None
    src, dst = str(ev.get("src_ip", "")), str(ev.get("dest_ip", ""))
    # The local host is the non-public side. If both are local, prefer the source.
    if src and not is_public(src):
        local = src
    elif dst and not is_public(dst):
        local = dst
    else:
        return None
    try:
        ts = parse_ts(str(ev.get("timestamp", "")))
    except ValueError:
        return None
    try:
        sev = int(alert.get("severity", 3))
    except (TypeError, ValueError):
        sev = 3
    return EveAlert(
        ts=ts,
        local_ip=local,
        severity=SEVERITY_MAP.get(sev, "low" if sev > 3 else "high"),
        signature=redact(str(alert.get("signature", "")))[:300],
        sid=int(alert.get("signature_id", 0) or 0),
        category=redact(str(alert.get("category", "")))[:120],
    )


class EveTailer:
    def __init__(self, eve_path: Path, state_file: Path, start_at_end: bool = True) -> None:
        self.eve_path = eve_path
        self.state_file = state_file
        self.start_at_end = start_at_end
        self._pending: Position | None = None

    def _load(self) -> Position | None:
        try:
            data = json.loads(self.state_file.read_text())
            return Position(int(data["inode"]), int(data["offset"]))
        except (FileNotFoundError, ValueError, KeyError, TypeError):
            return None

    def read(self) -> list[EveAlert]:
        """Read new complete lines. Call `commit()` once their alerts are queued."""
        self._pending = None
        try:
            st = os.stat(self.eve_path)
        except FileNotFoundError:
            return []
        saved = self._load()
        if saved is None:
            # First run: do not replay history that predates the shipper.
            offset = st.st_size if self.start_at_end else 0
        elif saved.inode != st.st_ino or st.st_size < saved.offset:
            log.info("eve.json rotated or truncated; reading from the start")
            offset = 0
        else:
            offset = saved.offset
        if offset >= st.st_size:
            self._pending = Position(st.st_ino, offset)
            return []
        with open(self.eve_path, "rb") as fh:
            fh.seek(offset)
            chunk = fh.read(MAX_READ_BYTES)
        end = chunk.rfind(b"\n")
        if end < 0:
            self._pending = Position(st.st_ino, offset)
            return []
        complete = chunk[: end + 1]
        out: list[EveAlert] = []
        for raw in complete.splitlines():
            ev = parse_event(raw.decode("utf-8", errors="replace"))
            if ev:
                out.append(ev)
        self._pending = Position(st.st_ino, offset + len(complete))
        return out

    def commit(self) -> None:
        if self._pending is None:
            return
        tmp = self.state_file.with_suffix(".tmp")
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps({"inode": self._pending.inode, "offset": self._pending.offset}))
        os.replace(tmp, self.state_file)
        self._pending = None


def to_alerts(events: list[EveAlert], resolve: Callable[[str], str | None]) -> tuple[list[tuple[str, EveAlert]], int]:
    """Pair events with device hashes. Returns (pairs, unattributed_count)."""
    pairs: list[tuple[str, EveAlert]] = []
    dropped = 0
    for ev in events:
        dh = resolve(ev.local_ip)
        if dh is None:
            dropped += 1
            continue
        pairs.append((dh, ev))
    return pairs, dropped
