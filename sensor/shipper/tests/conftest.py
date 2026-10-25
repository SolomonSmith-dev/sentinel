from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sentinel_shipper.anonymize import OuiDb
from sentinel_shipper.geo import GeoDb
from sentinel_shipper.state import State
from sentinel_shipper.windows import parse_line

FIXTURES = Path(__file__).parent / "fixtures"
SALT = "test-salt-not-a-secret"
TOKEN = "test-token-not-a-secret"
T0 = 1_761_370_740  # a minute boundary (T0 % 60 == 0)


def window_dict(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "window_start": T0,
        "window_s": 10,
        "iface": "eth0",
        "host": {"mac": "a4:83:e7:12:34:56", "ip": "192.168.1.20"},
        "pkts_out": 210, "pkts_in": 202,
        "bytes_out": 20311, "bytes_in": 120394,
        "syn_out": 6, "synack_in": 6,
        "distinct_dests": 2,
        "distinct_ports_out": 2,
        "dests": [
            {"ip": "142.250.72.14", "pkts": 80, "bytes": 60000, "syn": 1, "ports": [443]},
            {"ip": "192.168.1.1", "pkts": 10, "bytes": 900, "syn": 0, "ports": [53]},
        ],
        "inbound_sources": [
            {"ip": "142.250.72.14", "pkts": 150, "syn": 0, "distinct_ports": 1},
        ],
    }
    base.update(over)
    return base


def make_window(**over: Any):
    return parse_line(json.dumps(window_dict(**over)))


def write_window_file(directory: Path, start: int, hosts: list[dict[str, Any]]) -> Path:
    path = directory / f"{start}.ndjson"
    path.write_text("".join(json.dumps(h) + "\n" for h in hosts))
    return path


@pytest.fixture
def geo() -> GeoDb:
    return GeoDb.load(FIXTURES / "ip2country-v4.tsv")


@pytest.fixture
def oui() -> OuiDb:
    return OuiDb.load(FIXTURES / "oui.csv")


@pytest.fixture
def state(tmp_path: Path):
    s = State(tmp_path / "state" / "state.db")
    yield s
    s.close()
