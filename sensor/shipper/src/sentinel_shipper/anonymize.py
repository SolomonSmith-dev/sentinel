"""MAC anonymization and vendor lookup.

`device_hash` is the only device identifier that leaves the sensor host:
`dev-` + the first 6 hex chars of sha256(mac_lowercase + salt). Without the
salt it cannot be reversed by hashing all 2^48 MACs (or the much smaller set of
MACs under a known vendor prefix). Six hex chars is 16.7M buckets, plenty for a
home LAN, and short enough to read on a dashboard.
"""

from __future__ import annotations

import csv
import hashlib
import logging
import re
from pathlib import Path

log = logging.getLogger(__name__)

PRIVATE_MAC = "Private MAC"
UNKNOWN = "Unknown"
_HEX = re.compile(r"[^0-9a-f]")


def device_hash(mac: str, salt: str) -> str:
    digest = hashlib.sha256((mac.strip().lower() + salt).encode("utf-8")).hexdigest()
    return "dev-" + digest[:6]


def _mac_hex(mac: str) -> str:
    return _HEX.sub("", mac.lower())


def is_locally_administered(mac: str) -> bool:
    """Bit 1 of the first octet set: randomized / private MAC (phones, laptops)."""
    hexed = _mac_hex(mac)
    if len(hexed) < 2:
        return False
    return bool(int(hexed[:2], 16) & 0x02)


class OuiDb:
    """IEEE MA-L lookup from oui.csv (Registry,Assignment,Organization Name,Organization Address)."""

    def __init__(self, vendors: dict[str, str] | None = None) -> None:
        self._vendors = vendors or {}

    @classmethod
    def load(cls, path: Path) -> "OuiDb":
        vendors: dict[str, str] = {}
        try:
            with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
                for row in csv.DictReader(fh):
                    prefix = (row.get("Assignment") or "").strip().upper()
                    name = (row.get("Organization Name") or "").strip()
                    if len(prefix) == 6 and name:
                        vendors[prefix] = _clean_vendor(name)
        except FileNotFoundError:
            log.warning("OUI database %s not found; vendors will be Unknown", path)
        return cls(vendors)

    def __len__(self) -> int:
        return len(self._vendors)

    def vendor(self, mac: str) -> str:
        if is_locally_administered(mac):
            return PRIVATE_MAC
        prefix = _mac_hex(mac)[:6].upper()
        return self._vendors.get(prefix, UNKNOWN)


def _clean_vendor(name: str) -> str:
    # Vendor names are public registry data, but keep them short and free of
    # anything the privacy guard could mistake for an address.
    name = re.sub(r"\s+", " ", name)[:64]
    return name
