"""Isolation-forest anomaly scoring for 10 s host windows.

See ml/README.md for the reasoning. In short:

Features (FEATURES, schema version FEATURE_SCHEMA_VERSION):
    bytes_in, bytes_out, pkts, distinct_dests, distinct_ports  -> log1p
    syn_ratio = syn_out / pkts_out                              -> as is, in [0, 1]

Why log1p: the count features are heavy-tailed and span six orders of magnitude
(an idle plug sends 2 packets, a TV streaming 4K receives 30 000). An isolation
tree picks split points uniformly between a feature's min and max, so on a raw
scale almost every split lands in the empty space between "normal" and the one
huge value, and differences among ordinary hosts are invisible. log1p makes the
splits proportional (10 -> 100 matters as much as 10k -> 100k) and keeps 0 at 0.

Calibration: sklearn's `score_samples` returns the negated anomaly score of the
original paper, about -0.35 for typical points and toward -1 for outliers. We
flip the sign (raw = -score_samples, higher = more anomalous) and map it with a
piecewise-linear function anchored on the training distribution:

    raw == median(train)          -> 0.5
    raw == 99.9th pct(train)      -> 0.8
    linear in between and beyond, clipped to [0, 1]

So a calibrated 0.8 (the ml_anomaly threshold) reads as "more isolated than
99.9% of the windows this model was trained on", and scores are comparable
across retrains even though the raw scale shifts.
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from .mlcore import (  # noqa: F401  (re-exported)
    ALERT_THRESHOLD, CAL_HIGH_Q, CAL_LOW_Q, FEATURE_SCHEMA_VERSION, FEATURES, LOG_FEATURES,
    MIN_TRAIN_ROWS, Scorer, raw_features,
)

log = logging.getLogger(__name__)

def transform(rows: Sequence[Sequence[float]] | np.ndarray) -> np.ndarray:
    x = np.asarray(rows, dtype=np.float64).reshape(-1, len(FEATURES)).copy()
    x[:, :LOG_FEATURES] = np.log1p(np.clip(x[:, :LOG_FEATURES], 0.0, None))
    x[:, LOG_FEATURES:] = np.clip(x[:, LOG_FEATURES:], 0.0, 1.0)
    return x


@dataclass(frozen=True)
class Calibration:
    low: float  # raw score at CAL_LOW_Q of training
    high: float  # raw score at CAL_HIGH_Q of training

    @classmethod
    def fit(cls, raw_train: np.ndarray) -> "Calibration":
        low = float(np.percentile(raw_train, CAL_LOW_Q))
        high = float(np.percentile(raw_train, CAL_HIGH_Q))
        if not math.isfinite(high - low) or high - low < 1e-6:
            high = low + 1e-6  # degenerate (constant) training data
        return cls(low=low, high=high)

    def apply(self, raw: np.ndarray) -> np.ndarray:
        scaled = 0.5 + 0.3 * (raw - self.low) / (self.high - self.low)
        return np.clip(scaled, 0.0, 1.0)


@dataclass
class AnomalyModel:
    forest: IsolationForest
    calibration: Calibration
    trained_at: int
    n_rows: int
    schema_version: int = FEATURE_SCHEMA_VERSION
    features: tuple[str, ...] = FEATURES

    @classmethod
    def train(
        cls,
        rows: Sequence[Sequence[float]] | np.ndarray,
        *,
        random_state: int = 0,
        n_estimators: int = 200,
        now: int | None = None,
    ) -> "AnomalyModel":
        x = transform(rows)
        if len(x) < MIN_TRAIN_ROWS:
            raise ValueError(f"need at least {MIN_TRAIN_ROWS} rows to train, got {len(x)}")
        forest = IsolationForest(
            n_estimators=n_estimators,
            max_samples=min(256, len(x)),
            contamination="auto",
            random_state=random_state,
            n_jobs=1,
        )
        forest.fit(x)
        raw = -forest.score_samples(x)
        return cls(
            forest=forest,
            calibration=Calibration.fit(raw),
            trained_at=int(time.time() if now is None else now),
            n_rows=len(x),
        )

    def raw_scores(self, rows: Sequence[Sequence[float]] | np.ndarray) -> np.ndarray:
        return -self.forest.score_samples(transform(rows))

    def score(self, rows: Sequence[Sequence[float]] | np.ndarray) -> np.ndarray:
        """Calibrated scores in [0, 1], higher = more anomalous."""
        if len(rows) == 0:
            return np.zeros(0)
        return self.calibration.apply(self.raw_scores(rows))

    # persistence ------------------------------------------------------------
    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        joblib.dump(
            {
                "schema_version": self.schema_version,
                "features": list(self.features),
                "forest": self.forest,
                "calibration": {"low": self.calibration.low, "high": self.calibration.high},
                "trained_at": self.trained_at,
                "n_rows": self.n_rows,
            },
            tmp,
        )
        tmp.replace(path)

    @classmethod
    def load(cls, path: Path) -> "AnomalyModel | None":
        """Load a persisted model, or None if missing or built for another schema."""
        if not path.exists():
            return None
        try:
            # joblib is pickle: only ever load the file this process wrote into
            # its own state dir (not shared, not network-supplied).
            blob = joblib.load(path)
        except Exception as exc:  # corrupt file: retrain rather than crash
            log.warning("could not load model %s (%s); scoring disabled", path, type(exc).__name__)
            return None
        if blob.get("schema_version") != FEATURE_SCHEMA_VERSION or tuple(blob.get("features", ())) != FEATURES:
            log.warning("model %s has feature schema %s, want %s; ignoring it",
                        path, blob.get("schema_version"), FEATURE_SCHEMA_VERSION)
            return None
        cal = blob["calibration"]
        return cls(
            forest=blob["forest"],
            calibration=Calibration(low=float(cal["low"]), high=float(cal["high"])),
            trained_at=int(blob["trained_at"]),
            n_rows=int(blob["n_rows"]),
        )
