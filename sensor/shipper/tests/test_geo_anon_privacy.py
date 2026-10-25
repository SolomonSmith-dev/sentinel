from __future__ import annotations

import json

import pytest

from conftest import FIXTURES

from sentinel_shipper import privacy
from sentinel_shipper.anonymize import OuiDb, device_hash, is_locally_administered
from sentinel_shipper.geo import GeoDb, is_public


# --- geo -----------------------------------------------------------------------

@pytest.mark.parametrize("ip,cc", [
    ("8.8.8.8", "US"),
    ("8.8.8.0", "US"),      # range start
    ("8.8.8.255", "US"),    # range end
    ("1.0.0.1", "AU"),
    ("77.88.63.255", "RU"),
    ("185.60.218.35", "IE"),
    ("100.0.0.9", "??"),    # "None" in the source file
    ("8.8.9.0", "??"),      # gap between ranges
    ("2.0.0.1", "??"),       # before the first public range in the fixture
    ("223.255.255.1", "??"),  # past the last range
])
def test_geo_lookup(geo, ip, cc):
    assert geo.lookup(ip) == cc


@pytest.mark.parametrize("ip", [
    "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "127.0.0.1",
    "169.254.1.1", "224.0.0.251", "255.255.255.255", "fc00::1", "fe80::1", "not-an-ip", "",
])
def test_private_never_looked_up(geo, ip):
    assert not is_public(ip)
    assert geo.lookup(ip) is None
    with pytest.raises(ValueError):
        geo.country(ip)


def test_geo_missing_file_is_unknown(tmp_path):
    g = GeoDb.load(tmp_path / "missing.tsv")
    assert len(g) == 0 and g.lookup("8.8.8.8") == "??"


def test_geo_public_ipv6_is_unknown(geo):
    assert geo.lookup("2001:4860:4860::8888") == "??"


# --- anonymizer ----------------------------------------------------------------

def test_device_hash_format_and_determinism():
    h = device_hash("A4:83:E7:12:34:56", "salt-one")
    assert h == device_hash("a4:83:e7:12:34:56", "salt-one")
    assert h.startswith("dev-") and len(h) == 10
    int(h[4:], 16)


def test_device_hash_known_value():
    import hashlib
    expected = "dev-" + hashlib.sha256(b"a4:83:e7:12:34:56salt-one").hexdigest()[:6]
    assert device_hash("a4:83:e7:12:34:56", "salt-one") == expected


def test_device_hash_depends_on_salt():
    assert device_hash("a4:83:e7:12:34:56", "salt-one") != device_hash("a4:83:e7:12:34:56", "salt-two")


def test_vendor_lookup(oui):
    assert oui.vendor("a4:83:e7:12:34:56") == "Apple Inc."
    assert oui.vendor("B8-27-EB-00-00-01") == "Raspberry Pi Foundation"
    assert oui.vendor("f0:d5:bf:aa:bb:cc") == "Intel Corporate"
    assert oui.vendor("00:11:22:33:44:55") == "Unknown"


def test_private_mac(oui):
    # 0x02 bit of the first octet set -> locally administered (randomized)
    assert is_locally_administered("da:a1:19:00:00:01")
    assert oui.vendor("da:a1:19:00:00:01") == "Private MAC"
    assert oui.vendor("a6:83:e7:12:34:56") == "Private MAC"  # Apple prefix with LA bit flipped
    assert not is_locally_administered("a4:83:e7:12:34:56")


def test_oui_missing_file(tmp_path):
    assert OuiDb.load(tmp_path / "nope.csv").vendor("a4:83:e7:12:34:56") == "Unknown"


# --- privacy guard -------------------------------------------------------------

CLEAN = {"sensor_id": "sensor-01", "sent_at": 1761370800, "queue_depth": 0,
         "devices": [{"device_hash": "dev-3fa91c", "vendor": "Apple Inc.", "first_seen": 1761370740}],
         "windows": [{"device_hash": "dev-3fa91c", "ts": 1761370740, "duration_s": 60, "bytes_in": 1,
                      "bytes_out": 2, "pkts": 3, "distinct_dests": 1, "distinct_ports": 1,
                      "syn_ratio": 0.03, "score": None, "countries": {"US": 3, "??": 1}}],
         "alerts": [{"id": "6f1c0f0e-2b8a-4a51-9a63-0f7c6d1e2a10", "type": "suricata",
                     "device_hash": "dev-3fa91c", "ts": 1761370752, "severity": "high",
                     "detail": {"signature": "ET SCAN Nmap", "sid": 2010935, "category": "Attempted Recon"}}]}


def dumps(body) -> str:
    return json.dumps(body, separators=(",", ":"))


def test_guard_passes_clean_body():
    privacy.check(dumps(CLEAN))


@pytest.mark.parametrize("leak,kind", [
    ("192.168.1.20", "ipv4"),
    ("8.8.8.8", "ipv4"),
    ("a4:83:e7:12:34:56", "mac"),
    ("A4-83-E7-12-34-56", "mac"),
    ("fe80::1", "ipv6"),
    ("2001:db8:85a3:0:0:8a2e:370:7334", "ipv6"),
])
def test_guard_blocks_addresses(leak, kind):
    body = json.loads(dumps(CLEAN))
    body["alerts"][0]["detail"]["signature"] = f"ET SCAN from {leak}"
    with pytest.raises(privacy.PrivacyViolation) as exc:
        privacy.check(dumps(body))
    assert kind in exc.value.kinds
    assert leak not in str(exc.value)  # never echo the address


def test_guard_blocks_wan_ip_even_without_pattern():
    # A WAN IP is caught by the IPv4 pattern too; the explicit check must name it.
    body = dumps(CLEAN).replace("Nmap", "Nmap 81.2.69.160")
    with pytest.raises(privacy.PrivacyViolation) as exc:
        privacy.check(body, wan_ip="81.2.69.160")
    assert "wan_ip" in exc.value.kinds


def test_redact_scrubs_free_text():
    s = privacy.redact("ET POLICY 10.0.0.1 -> aa:bb:cc:dd:ee:ff via fe80::1")
    assert privacy.violations(s) == []


# --- parity with the Worker -----------------------------------------------------
# Same vectors as api/test/pii-vectors.json (vitest asserts the Worker side).
import json  # noqa: E402
from pathlib import Path  # noqa: E402

_VECTORS = json.loads((Path(__file__).resolve().parents[3] / "api" / "test" / "pii-vectors.json").read_text())


@pytest.mark.parametrize("vec", _VECTORS, ids=[v["text"] for v in _VECTORS])
def test_privacy_matches_worker_vectors(vec):
    assert bool(privacy.violations(vec["text"])) is vec["pii"]
    # Anything the Worker would reject must be fully scrubbed by redact().
    assert privacy.violations(privacy.redact(vec["text"])) == []


def test_vectors_cover_required_cases():
    texts = {v["text"] for v in _VECTORS}
    assert {"v2.0.1.3", "0.03", "dev-3fa91c", "3f2504e0-4f89-11d3-9a0c-0305e82c3301"} <= texts
    assert any("beacon" in t for t in texts)
