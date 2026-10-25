from __future__ import annotations

import numpy as np

from conftest import make_window

from sentinel_shipper.model import FEATURES, AnomalyModel, Calibration, Scorer, raw_features, transform


def benign(n: int, seed: int = 0) -> np.ndarray:
    """Plausible home-LAN 10 s windows: a mix of idle, browsing and streaming hosts."""
    rng = np.random.default_rng(seed)
    kind = rng.choice(3, size=n, p=[0.5, 0.35, 0.15])
    pkts = np.where(kind == 0, rng.lognormal(2, 0.6, n), np.where(kind == 1, rng.lognormal(5, 0.8, n),
                                                                  rng.lognormal(7.5, 0.4, n)))
    bytes_in = pkts * np.where(kind == 2, rng.normal(1300, 100, n), rng.normal(600, 150, n)).clip(60)
    bytes_out = pkts * rng.normal(120, 30, n).clip(60)
    dests = np.where(kind == 0, rng.integers(1, 3, n), rng.integers(2, 25, n))
    ports = np.minimum(dests, rng.integers(1, 5, n))
    syn = rng.beta(1, 40, n)
    return np.column_stack([bytes_in, bytes_out, pkts, dests, ports, syn])


def test_raw_features_from_window():
    w = make_window(pkts_in=10, pkts_out=40, syn_out=4, distinct_ports_out=3)
    vec = raw_features(w)
    assert len(vec) == len(FEATURES)
    assert vec[2] == 50 and vec[4] == 3 and vec[5] == 0.1


def test_transform_logs_counts_only():
    x = transform([[0, 9, 99, 0, 0, 0.5]])
    assert np.allclose(x[0, :5], np.log1p([0, 9, 99, 0, 0]))
    assert x[0, 5] == 0.5


def test_train_and_score_range():
    model = AnomalyModel.train(benign(3000), random_state=0)
    scores = model.score(benign(500, seed=1))
    assert scores.min() >= 0.0 and scores.max() <= 1.0
    # calibrated so typical traffic sits near 0.5 and almost none crosses 0.8
    assert 0.35 < float(np.median(scores)) < 0.65
    assert float(np.mean(scores > 0.8)) < 0.02


def test_flood_and_scan_rows_score_higher():
    model = AnomalyModel.train(benign(3000), random_state=0)
    flood = [[2e6, 3e7, 150_000, 1, 1, 0.98]]
    scan = [[4e3, 6e4, 1000, 3, 800, 0.95]]
    normal = model.score(benign(500, seed=2))
    assert model.score(flood)[0] > normal.max()
    assert model.score(scan)[0] > np.percentile(normal, 99)
    assert model.score(flood)[0] > 0.8


def test_calibration_mapping():
    cal = Calibration(low=0.4, high=0.6)
    assert np.allclose(cal.apply(np.array([0.4, 0.6, 0.0, 2.0])), [0.5, 0.8, 0.0, 1.0])


def test_calibration_degenerate():
    cal = Calibration.fit(np.full(100, 0.42))
    assert cal.high > cal.low
    assert np.all((cal.apply(np.array([0.1, 0.42, 0.9])) >= 0) & (cal.apply(np.array([0.1, 0.42, 0.9])) <= 1))


def test_persist_roundtrip(tmp_path):
    model = AnomalyModel.train(benign(1000), random_state=0, now=123)
    path = tmp_path / "model.joblib"
    model.save(path)
    loaded = AnomalyModel.load(path)
    assert loaded is not None and loaded.trained_at == 123 and loaded.n_rows == 1000
    rows = benign(50, seed=3)
    assert np.allclose(loaded.score(rows), model.score(rows))


def test_schema_mismatch_is_ignored(tmp_path):
    import joblib
    path = tmp_path / "model.joblib"
    joblib.dump({"schema_version": 999, "features": ["x"]}, path)
    assert AnomalyModel.load(path) is None


def test_missing_model_scores_null(tmp_path):
    assert AnomalyModel.load(tmp_path / "absent.joblib") is None
    assert Scorer(None).score([[1, 2, 3, 4, 5, 0.1]]) == [None]


def test_too_few_rows_refused():
    import pytest
    with pytest.raises(ValueError):
        AnomalyModel.train(benign(10))
