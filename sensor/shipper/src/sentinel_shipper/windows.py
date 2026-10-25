"""Parsing the capture's 10 s ndjson windows (see docs/sensor-format.md).

These records hold raw IPs and MACs. They never leave this process: everything
shipped is derived from them through `anonymize`, `geo` and `rollup`.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

WINDOW_S = 10
BUCKET_S = 60


@dataclass(frozen=True)
class Dest:
    ip: str
    pkts: int
    bytes: int
    syn: int
    ports: tuple[int, ...]


@dataclass(frozen=True)
class InboundSource:
    ip: str
    pkts: int
    syn: int
    distinct_ports: int


@dataclass(frozen=True)
class HostWindow:
    """One local host in one 10 s window."""

    window_start: int
    window_s: int
    mac: str
    ip: str
    pkts_out: int
    pkts_in: int
    bytes_out: int
    bytes_in: int
    syn_out: int
    synack_in: int
    distinct_dests: int
    distinct_ports_out: int
    dests: tuple[Dest, ...] = field(default=())
    inbound_sources: tuple[InboundSource, ...] = field(default=())

    @property
    def pkts(self) -> int:
        return self.pkts_in + self.pkts_out

    @property
    def bucket(self) -> int:
        return self.window_start - self.window_start % BUCKET_S


def _int(obj: dict, key: str) -> int:
    value = obj.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"field {key!r} is not a number")
    return int(value)


def parse_line(line: str) -> HostWindow:
    obj = json.loads(line)
    if not isinstance(obj, dict):
        raise ValueError("line is not a JSON object")
    host = obj.get("host") or {}
    mac = str(host.get("mac", "")).lower()
    if not mac:
        raise ValueError("missing host.mac")
    dests = tuple(
        Dest(
            ip=str(d.get("ip", "")),
            pkts=_int(d, "pkts"),
            bytes=_int(d, "bytes"),
            syn=_int(d, "syn"),
            ports=tuple(int(p) for p in d.get("ports", [])),
        )
        for d in obj.get("dests", [])
    )
    sources = tuple(
        InboundSource(
            ip=str(s.get("ip", "")),
            pkts=_int(s, "pkts"),
            syn=_int(s, "syn"),
            distinct_ports=_int(s, "distinct_ports"),
        )
        for s in obj.get("inbound_sources", [])
    )
    return HostWindow(
        window_start=_int(obj, "window_start"),
        window_s=_int(obj, "window_s") or WINDOW_S,
        mac=mac,
        ip=str(host.get("ip", "")),
        pkts_out=_int(obj, "pkts_out"),
        pkts_in=_int(obj, "pkts_in"),
        bytes_out=_int(obj, "bytes_out"),
        bytes_in=_int(obj, "bytes_in"),
        syn_out=_int(obj, "syn_out"),
        synack_in=_int(obj, "synack_in"),
        distinct_dests=_int(obj, "distinct_dests"),
        distinct_ports_out=_int(obj, "distinct_ports_out"),
        dests=dests,
        inbound_sources=sources,
    )


def read_window_file(path: Path) -> list[HostWindow]:
    """Parse one finished window file. Bad lines are skipped and logged (no content)."""
    out: list[HostWindow] = []
    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                out.append(parse_line(line))
            except (ValueError, TypeError, AttributeError) as exc:
                log.warning("skipping bad line %s:%d (%s)", path.name, lineno, type(exc).__name__)
    return out


def file_window_start(path: Path) -> int | None:
    """Window start from the `<window_start>.ndjson` file name."""
    stem = path.name.removesuffix(".ndjson")
    return int(stem) if stem.isdigit() else None


def list_finished(windows_dir: Path) -> list[Path]:
    """Finished window files, oldest first. `.ndjson.tmp` files are never returned."""
    if not windows_dir.is_dir():
        return []
    files = [p for p in windows_dir.iterdir() if p.is_file() and p.name.endswith(".ndjson")]
    return sorted(files, key=lambda p: (file_window_start(p) or 0, p.name))


def complete_buckets(files: list[Path], now: float, grace_s: int = 15) -> list[Path]:
    """Return only files whose 60 s bucket is complete.

    The API upserts windows on (device_hash, ts), so shipping a half-filled
    minute and then the other half would overwrite the first half. A bucket is
    complete once the capture has written any window past its end, or once its
    end plus a grace period has passed on the wall clock.
    """
    starts = [file_window_start(p) for p in files]
    known = [s for s in starts if s is not None]
    newest = max(known) if known else None
    ready: list[Path] = []
    for path, start in zip(files, starts):
        if start is None:
            ready.append(path)  # unparseable name; read it, it carries its own timestamps
            continue
        bucket_end = start - start % BUCKET_S + BUCKET_S
        if (newest is not None and newest >= bucket_end) or now >= bucket_end + grace_s:
            ready.append(path)
    return ready
