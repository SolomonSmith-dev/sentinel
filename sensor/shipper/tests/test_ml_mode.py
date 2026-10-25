from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

from sentinel_shipper import mlmode

NO_NUMPY_SCRIPT = textwrap.dedent("""
    import sys
    for m in ("numpy", "scipy", "sklearn", "joblib"):
        sys.modules[m] = None  # any import of these now raises ImportError
    import os, tempfile, pathlib
    os.environ["SENTINEL_ML"] = "off"
    sys.path.insert(0, {tests!r})
    from conftest import T0, make_window, window_dict, write_window_file, SALT
    from sentinel_shipper.config import Settings
    from sentinel_shipper.rules import RuleEngine
    from sentinel_shipper.pipeline import Pipeline
    from sentinel_shipper.mlcore import Scorer, ALERT_THRESHOLD
    from sentinel_shipper.training import Trainer
    from sentinel_shipper.geo import GeoDb
    from sentinel_shipper.anonymize import OuiDb
    from sentinel_shipper.queue import DiskQueue
    from sentinel_shipper.state import State
    from sentinel_shipper import mlmode
    assert mlmode.ml_enabled() is False
    tmp = pathlib.Path(tempfile.mkdtemp())
    fx = pathlib.Path({tests!r}) / "fixtures"
    wdir = tmp / "windows"; wdir.mkdir()
    st = State(tmp / "state" / "state.db")
    write_window_file(wdir, T0, [window_dict()])
    write_window_file(wdir, T0 + 10, [window_dict(window_start=T0 + 10)])
    p = Pipeline(sensor_id="s", salt=SALT, windows_dir=wdir, state=st, queue=DiskQueue(tmp / "state"),
                 geo=GeoDb.load(fx / "ip2country-v4.tsv"), oui=OuiDb.load(fx / "oui.csv"), scorer=Scorer(None))
    res = p.tick(now=T0 + 600)
    assert res.windows >= 1 and res.batches >= 1, res
    tr = Trainer(st, Scorer(None), tmp / "m.joblib", enabled=False)
    assert tr.maybe_train(now=T0) is False and tr.train_now(now=T0) is False
    assert "numpy" not in [k for k, v in sys.modules.items() if v is not None]
    assert "sentinel_shipper.model" not in sys.modules
    print("OK")
""")


def test_rules_pipeline_shipping_work_without_numpy():
    from pathlib import Path
    tests = str(Path(__file__).parent)
    script = NO_NUMPY_SCRIPT.format(tests=tests)
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0 and "OK" in proc.stdout, proc.stderr


def test_mode_parsing():
    assert mlmode.ml_mode({}) == "auto"
    assert mlmode.ml_mode({"SENTINEL_ML": " OFF "}) == "off"
    assert mlmode.ml_mode({"SENTINEL_ML": "bogus"}) == "auto"


def test_off_never_probes(monkeypatch):
    monkeypatch.setattr(mlmode.subprocess, "run", lambda *a, **k: pytest.fail("probe ran"))
    assert mlmode.ml_enabled({"SENTINEL_ML": "off"}) is False


def test_on_skips_probe(monkeypatch):
    monkeypatch.setattr(mlmode.subprocess, "run", lambda *a, **k: pytest.fail("probe ran"))
    assert mlmode.ml_enabled({"SENTINEL_ML": "on"}) is True


def test_auto_falls_back_on_sigill(monkeypatch, caplog):
    monkeypatch.setattr(mlmode.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, -4, b"", b""))
    with caplog.at_level("WARNING"):
        assert mlmode.ml_enabled({}) is False
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1 and "SIGILL" in warnings[0].getMessage()


def test_auto_falls_back_on_timeout(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired("x", 1)
    monkeypatch.setattr(mlmode.subprocess, "run", boom)
    assert mlmode.ml_enabled({}) is False


def test_auto_enables_when_probe_succeeds(monkeypatch):
    monkeypatch.setattr(mlmode.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 0, b"", b""))
    assert mlmode.ml_enabled({"SENTINEL_ML": "auto"}) is True


def test_real_probe_runs_here():
    ok, detail = mlmode.probe_ml()
    assert ok, detail
