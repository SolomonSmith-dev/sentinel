"""SENTINEL_ML = auto | on | off, and the import-safety probe.

numpy/scipy/sklearn wheels can use instructions an old CPU lacks (the sensor's
Core 2 Duo has SSE4.1 but no SSE4.2/POPCNT/AVX). That kills the interpreter
with SIGILL at import, which cannot be caught in-process, so `auto` runs the
import and a tiny fit in a child process first. No numpy import here.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
from typing import Mapping

log = logging.getLogger(__name__)

PROBE_TIMEOUT_S = 60.0
PROBE_CODE = (
    "import numpy, scipy, sklearn.ensemble, joblib\n"
    "rng = numpy.random.RandomState(0)\n"
    "x = rng.rand(50, 6)\n"
    "f = sklearn.ensemble.IsolationForest(n_estimators=10, random_state=0, n_jobs=1).fit(x)\n"
    "f.score_samples(x)\n"
)


def ml_mode(env: Mapping[str, str] | None = None) -> str:
    e = os.environ if env is None else env
    value = (e.get("SENTINEL_ML") or "auto").strip().lower()
    if value not in ("auto", "on", "off"):
        log.warning("SENTINEL_ML=%r is not auto|on|off; using auto", value)
        return "auto"
    return value


def probe_ml(timeout_s: float = PROBE_TIMEOUT_S) -> tuple[bool, str]:
    """Run the numpy/sklearn import and a tiny fit in a child. Returns (ok, detail)."""
    try:
        proc = subprocess.run([sys.executable, "-c", PROBE_CODE], capture_output=True,
                              timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return False, f"probe timed out after {timeout_s:.0f}s"
    except OSError as exc:
        return False, f"probe could not start ({type(exc).__name__})"
    rc = proc.returncode
    if rc == 0:
        return True, "ok"
    if rc < 0:
        try:
            name = signal.Signals(-rc).name
        except ValueError:
            name = f"signal {-rc}"
        return False, f"probe killed by {name}"
    tail = (proc.stderr or b"").decode("utf-8", "replace").strip().splitlines()
    return False, f"probe exited {rc}" + (f": {tail[-1]}" if tail else "")


def ml_enabled(env: Mapping[str, str] | None = None) -> bool:
    mode = ml_mode(env)
    if mode == "off":
        log.info("SENTINEL_ML=off: anomaly scores are null; rules and shipping run")
        return False
    if mode == "on":
        return True
    ok, detail = probe_ml()
    if ok:
        log.info("ML probe passed; anomaly scoring enabled")
        return True
    log.warning("ML DISABLED: %s. numpy/sklearn is unusable on this CPU; scores will be null "
                "and no model will be trained. Rules and shipping continue. Set SENTINEL_ML=on "
                "to skip this probe.", detail)
    return False
