from __future__ import annotations

from conftest import T0, make_window

from sentinel_shipper.rules import RuleEngine


def engine(state, geo) -> RuleEngine:
    return RuleEngine(state, geo, "sensor-test")


def kinds(alerts) -> list[str]:
    return sorted(a.type for a in alerts)


OLD = T0 - 10 * 86400  # device known for 10 days: past every warm-up


def eval_one(state, geo, w, *, is_new=False, first_seen=OLD, score=None):
    state.begin()
    alerts = engine(state, geo).evaluate(w, "dev-aaaaaa", is_new, first_seen, score)
    state.commit()
    return alerts


# --- flood -------------------------------------------------------------------

def test_flood_fires_on_pkts_to_one_dest(state, geo):
    w = make_window(dests=[{"ip": "8.8.8.8", "pkts": 20_001, "bytes": 1, "syn": 0, "ports": [53]}])
    alerts = eval_one(state, geo, w)
    flood = [a for a in alerts if a.type == "flood"]
    assert len(flood) == 1
    assert flood[0].severity == "critical"
    assert flood[0].detail["kind"] == "pkts_to_one_dest"
    assert flood[0].detail["country"] == "US"


def test_flood_silent_at_threshold(state, geo):
    w = make_window(dests=[{"ip": "8.8.8.8", "pkts": 20_000, "bytes": 1, "syn": 0, "ports": [53]}])
    assert "flood" not in kinds(eval_one(state, geo, w))


def test_flood_fires_on_inbound_syn(state, geo):
    w = make_window(inbound_sources=[{"ip": "9.9.9.9", "pkts": 600, "syn": 501, "distinct_ports": 1}])
    alerts = [a for a in eval_one(state, geo, w) if a.type == "flood"]
    assert alerts and alerts[0].detail["kind"] == "syn_from_one_source"


def test_flood_silent_inbound_syn_at_threshold(state, geo):
    w = make_window(inbound_sources=[{"ip": "9.9.9.9", "pkts": 600, "syn": 500, "distinct_ports": 1}])
    assert "flood" not in kinds(eval_one(state, geo, w))


def test_flood_fires_on_syn_out(state, geo):
    w = make_window(syn_out=501, pkts_out=600)
    alerts = [a for a in eval_one(state, geo, w) if a.type == "flood"]
    assert alerts and alerts[0].detail["kind"] == "syn_out"


def test_flood_silent_syn_out_at_threshold(state, geo):
    assert "flood" not in kinds(eval_one(state, geo, make_window(syn_out=500, pkts_out=600)))


# --- port scan -----------------------------------------------------------------

def test_port_scan_outbound(state, geo):
    alerts = [a for a in eval_one(state, geo, make_window(distinct_ports_out=21)) if a.type == "port_scan"]
    assert len(alerts) == 1 and alerts[0].severity == "high"
    assert alerts[0].detail["direction"] == "outbound"


def test_port_scan_inbound(state, geo):
    w = make_window(inbound_sources=[{"ip": "77.88.1.2", "pkts": 40, "syn": 40, "distinct_ports": 21}])
    alerts = [a for a in eval_one(state, geo, w) if a.type == "port_scan"]
    assert alerts and alerts[0].detail == {"direction": "inbound", "distinct_ports": 21,
                                           "window_s": 10, "country": "RU"}


def test_port_scan_silent_at_threshold(state, geo):
    w = make_window(distinct_ports_out=20,
                    inbound_sources=[{"ip": "77.88.1.2", "pkts": 40, "syn": 0, "distinct_ports": 20}])
    assert "port_scan" not in kinds(eval_one(state, geo, w))


# --- new device ----------------------------------------------------------------

def test_new_device_fires_only_when_new(state, geo):
    assert "new_device" in kinds(eval_one(state, geo, make_window(), is_new=True))
    assert "new_device" not in kinds(eval_one(state, geo, make_window(window_start=T0 + 600)))


def test_new_device_via_state(state):
    state.begin()
    assert state.upsert_device("dev-abcdef", "Apple Inc.", T0) is True
    assert state.upsert_device("dev-abcdef", "Apple Inc.", T0 + 10) is False
    state.commit()


# --- geo anomaly ---------------------------------------------------------------

def to(ip: str) -> list[dict]:
    return [{"ip": ip, "pkts": 5, "bytes": 500, "syn": 0, "ports": [443]}]


def test_geo_anomaly_new_country(state, geo):
    eval_one(state, geo, make_window(window_start=T0, dests=to("8.8.8.8")))
    alerts = eval_one(state, geo, make_window(window_start=T0 + 400, dests=to("77.88.1.1")))
    g = [a for a in alerts if a.type == "geo_anomaly"]
    assert len(g) == 1 and g[0].severity == "medium" and g[0].detail["country"] == "RU"


def test_geo_anomaly_silent_for_known_country(state, geo):
    eval_one(state, geo, make_window(window_start=T0, dests=to("77.88.1.1")))
    alerts = eval_one(state, geo, make_window(window_start=T0 + 400, dests=to("77.88.2.2")))
    assert "geo_anomaly" not in kinds(alerts)


def test_geo_anomaly_fires_again_after_seven_days(state, geo):
    eval_one(state, geo, make_window(window_start=T0, dests=to("77.88.1.1")))
    later = T0 + 8 * 86400
    alerts = eval_one(state, geo, make_window(window_start=later, dests=to("77.88.1.1")))
    assert "geo_anomaly" in kinds(alerts)


def test_geo_anomaly_suppressed_in_first_day(state, geo):
    first_seen = T0
    alerts = eval_one(state, geo, make_window(window_start=T0 + 3600, dests=to("77.88.1.1")),
                      first_seen=first_seen)
    assert "geo_anomaly" not in kinds(alerts)
    # ... but the country was still learned, so day two does not alert for it
    alerts = eval_one(state, geo, make_window(window_start=T0 + 90_000, dests=to("77.88.1.1")),
                      first_seen=first_seen)
    assert "geo_anomaly" not in kinds(alerts)


def test_geo_ignores_private_and_unknown(state, geo):
    alerts = eval_one(state, geo, make_window(dests=to("10.0.0.5") + to("100.0.0.1")))
    assert "geo_anomaly" not in kinds(alerts)


# --- ml ------------------------------------------------------------------------

def test_ml_anomaly_threshold(state, geo):
    assert "ml_anomaly" not in kinds(eval_one(state, geo, make_window(), score=0.8))
    a = [x for x in eval_one(state, geo, make_window(window_start=T0 + 10), score=0.81) if x.type == "ml_anomaly"]
    assert a and a[0].severity == "high" and a[0].detail["score"] == 0.81


def test_ml_anomaly_none_score_never_fires(state, geo):
    assert "ml_anomaly" not in kinds(eval_one(state, geo, make_window(), score=None))


# --- debounce ------------------------------------------------------------------

def test_debounce_same_type_same_device(state, geo):
    scan = dict(distinct_ports_out=50)
    first = eval_one(state, geo, make_window(window_start=T0, **scan))
    again = eval_one(state, geo, make_window(window_start=T0 + 290, **scan))
    after = eval_one(state, geo, make_window(window_start=T0 + 300, **scan))
    assert kinds(first).count("port_scan") == 1
    assert "port_scan" not in kinds(again)
    assert kinds(after).count("port_scan") == 1


def test_debounce_is_per_device_and_type(state, geo):
    e = engine(state, geo)
    w = make_window(distinct_ports_out=50, syn_out=900, pkts_out=1000)
    state.begin()
    a1 = e.evaluate(w, "dev-111111", False, OLD, None)
    a2 = e.evaluate(w, "dev-222222", False, OLD, None)
    state.commit()
    assert {"flood", "port_scan"} <= set(kinds(a1))
    assert kinds(a2) == kinds(a1)  # other device: not debounced by the first


def test_alert_ids_are_deterministic(state, geo, tmp_path):
    from sentinel_shipper.state import State
    w = make_window(distinct_ports_out=50)
    a = eval_one(state, geo, w)
    other = State(tmp_path / "other.db")
    other.begin()
    b = RuleEngine(other, geo, "sensor-test").evaluate(w, "dev-aaaaaa", False, OLD, None)
    other.commit()
    other.close()
    assert [x.id for x in a] == [x.id for x in b]
