"""Durable on-disk FIFO of ingest batches.

One JSON file per batch in `<state>/queue/`, named `<created_ms>-<seq>.json`
so lexical order is FIFO order. Writes go to a temp file, are fsynced, renamed
into place and the directory is fsynced, so after `put()` returns the batch
survives a crash or power loss. A batch is removed only after the API accepts
it (200 ok or duplicate) or it is quarantined.

Cap: batches older than 24 h are dropped oldest-first (and logged), as is
anything beyond `max_items`, so a long outage cannot fill the disk.
"""

from __future__ import annotations

import itertools
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

MAX_AGE_S = 24 * 3600
MAX_ITEMS = 24 * 3600 // 30  # one batch per 30 s tick for 24 h


@dataclass(frozen=True)
class Item:
    path: Path
    created: float

    def load(self) -> dict[str, Any]:
        return json.loads(self.path.read_text(encoding="utf-8"))


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    _fsync_dir(path.parent)


class DiskQueue:
    def __init__(self, root: Path, max_age_s: int = MAX_AGE_S, max_items: int = MAX_ITEMS) -> None:
        self.dir = root / "queue"
        self.quarantine_dir = root / "quarantine"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.max_age_s = max_age_s
        self.max_items = max_items
        self._seq = itertools.count()
        for stale in self.dir.glob("*.tmp"):  # half-written by a crash: never acknowledged
            stale.unlink(missing_ok=True)

    def items(self) -> list[Item]:
        out = []
        for p in sorted(self.dir.glob("*.json")):
            try:
                created = int(p.name.split("-", 1)[0]) / 1000.0
            except ValueError:
                created = p.stat().st_mtime
            out.append(Item(p, created))
        return out

    def __len__(self) -> int:
        return sum(1 for _ in self.dir.glob("*.json"))

    def put(self, body: dict[str, Any], now: float | None = None) -> Path:
        now = time.time() if now is None else now
        name = f"{int(now * 1000):014d}-{os.getpid()}-{next(self._seq):06d}.json"
        path = self.dir / name
        atomic_write(path, json.dumps(body, separators=(",", ":")).encode("utf-8"))
        self.enforce_cap(now)
        return path

    def update(self, item: Item, body: dict[str, Any]) -> None:
        atomic_write(item.path, json.dumps(body, separators=(",", ":")).encode("utf-8"))

    def remove(self, item: Item) -> None:
        item.path.unlink(missing_ok=True)
        _fsync_dir(self.dir)

    def quarantine(self, item: Item, reason: str) -> Path:
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        dest = self.quarantine_dir / item.path.name
        os.replace(item.path, dest)
        (self.quarantine_dir / (item.path.name + ".reason")).write_text(reason + "\n")
        log.error("quarantined batch %s: %s", item.path.name, reason)
        return dest

    def enforce_cap(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        items = self.items()
        dropped = 0
        for it in items:
            too_old = now - it.created > self.max_age_s
            too_many = len(items) - dropped > self.max_items
            if not (too_old or too_many):
                break
            self.remove(it)
            dropped += 1
        if dropped:
            log.warning("queue cap: dropped %d oldest batch(es) (older than %d s or over %d items)",
                        dropped, self.max_age_s, self.max_items)
        return dropped
