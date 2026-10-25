"""Country lookup over iptoasn.com's ip2country-v4.tsv (PDDL).

The file is sorted, non-overlapping ranges: `range_start<TAB>range_end<TAB>CC`.
We load the starts into an array and binary-search: O(log n) per lookup, about
20 comparisons for the full table, with no external service and no network
call per packet.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from array import array
from bisect import bisect_right
from functools import lru_cache
from pathlib import Path

log = logging.getLogger(__name__)

UNKNOWN = "??"
_CC = re.compile(r"^[A-Z]{2}$")


@lru_cache(maxsize=65536)
def is_public(ip: str) -> bool:
    """True only for globally routable addresses. RFC1918, CGNAT (100.64/10),
    loopback, link-local, ULA, multicast and reserved ranges are all False and
    are never looked up."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


class GeoDb:
    def __init__(self, starts: array, ends: array, countries: list[str]) -> None:
        self._starts = starts
        self._ends = ends
        self._countries = countries

    @classmethod
    def empty(cls) -> "GeoDb":
        return cls(array("I"), array("I"), [])

    @classmethod
    def load(cls, path: Path) -> "GeoDb":
        rows: list[tuple[int, int, str]] = []
        try:
            with path.open("r", encoding="ascii", errors="replace") as fh:
                for line in fh:
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) < 3:
                        continue
                    try:
                        start = int(ipaddress.IPv4Address(parts[0].strip()))
                        end = int(ipaddress.IPv4Address(parts[1].strip()))
                    except ValueError:
                        continue
                    cc = parts[2].strip().upper()
                    rows.append((start, end, cc if _CC.match(cc) else UNKNOWN))
        except FileNotFoundError:
            log.warning("geo database %s not found; all countries will be ??", path)
            return cls.empty()
        rows.sort()
        countries: dict[str, str] = {}
        return cls(
            array("I", (r[0] for r in rows)),
            array("I", (r[1] for r in rows)),
            [countries.setdefault(r[2], r[2]) for r in rows],
        )

    def __len__(self) -> int:
        return len(self._starts)

    def country(self, ip: str) -> str:
        if not is_public(ip):
            raise ValueError("private or invalid address; callers must filter with is_public")
        try:
            value = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return UNKNOWN  # IPv6: the v4 table cannot answer
        i = bisect_right(self._starts, value) - 1
        if i < 0 or value > self._ends[i]:
            return UNKNOWN
        return self._countries[i]

    def lookup(self, ip: str) -> str | None:
        """Country for a public address, None for a private one."""
        if not is_public(ip):
            return None
        return self.country(ip)
