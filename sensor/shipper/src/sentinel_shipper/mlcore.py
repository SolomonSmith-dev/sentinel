"""Pure-Python ML constants and helpers. Must never import numpy/scipy/sklearn.

The rules engine, pipeline and trainer import from here so a CPU that cannot
run the numpy wheels (SIGILL at import) cannot take the shipper down with it.
The heavy code lives in `model.py` and is imported lazily, only when ML is on.
"""

from __future__ import annotations

from typing import Any, Sequence

from .windows import HostWindow

FEATURE_SCHEMA_VERSION = 1
FEATURES: tuple[str, ...] = (
    "bytes_in",
    "bytes_out",
    "pkts",
    "distinct_dests",
    "distinct_ports",
    "syn_ratio",
)
LOG_FEATURES = 5  # the first five are counts and get log1p
ALERT_THRESHOLD = 0.8
CAL_LOW_Q = 50.0
CAL_HIGH_Q = 99.9
MIN_TRAIN_ROWS = 200


def raw_features(w: HostWindow) -> tuple[float, ...]:
    """Untransformed feature vector, as stored in the feature store."""
    syn_ratio = w.syn_out / w.pkts_out if w.pkts_out > 0 else 0.0
    return (
        float(w.bytes_in),
        float(w.bytes_out),
        float(w.pkts),
        float(w.distinct_dests),
        float(w.distinct_ports_out),
        float(min(max(syn_ratio, 0.0), 1.0)),
    )


class Scorer:
    """Holds the current model (or none). Rules run regardless."""

    def __init__(self, model: Any | None = None) -> None:
        self.model = model

    def score(self, rows: Sequence[Sequence[float]]) -> list[float | None]:
        if self.model is None or not rows:
            return [None] * len(rows)
        return [round(float(s), 4) for s in self.model.score(rows)]
