"""Retraining policy: nightly at a fixed local time, plus bootstrap.

Bootstrap: while no model exists, try to train (at startup and then at most
hourly) as soon as the feature store spans at least 2 hours. Until then the
score is null and only the rules run.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .mlcore import MIN_TRAIN_ROWS, Scorer
from .state import SEVEN_DAYS, State

log = logging.getLogger(__name__)

MIN_SPAN_S = 2 * 3600
TRAIN_SAMPLE = 100_000
BOOTSTRAP_RETRY_S = 3600


def next_run(after: datetime, hh: int, mm: int) -> datetime:
    candidate = after.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if candidate <= after:
        candidate += timedelta(days=1)
    return candidate


@dataclass
class Trainer:
    state: State
    scorer: Scorer
    model_path: Path
    hh: int = 3
    mm: int = 30
    enabled: bool = True  # False when SENTINEL_ML disables ML: never train, never import model
    _next_nightly: datetime | None = field(default=None, init=False)
    _next_bootstrap: float = field(default=0.0, init=False)

    def train_now(self, now: float | None = None) -> bool:
        if not self.enabled:
            return False
        now = time.time() if now is None else now
        if self.state.feature_span_s() < MIN_SPAN_S:
            log.info("not training: under 2 h of feature rows")
            return False
        rows = self.state.feature_rows(int(now) - SEVEN_DAYS, TRAIN_SAMPLE)
        if len(rows) < MIN_TRAIN_ROWS:
            log.info("not training: only %d feature rows", len(rows))
            return False
        from .model import AnomalyModel  # lazy: numpy/sklearn only when ML is on

        started = time.monotonic()
        model = AnomalyModel.train(rows, now=int(now))
        model.save(self.model_path)
        self.scorer.model = model
        log.info("trained isolation forest on %d rows in %.1f s", len(rows), time.monotonic() - started)
        return True

    def maybe_train(self, now: float | None = None) -> bool:
        if not self.enabled:
            return False
        now = time.time() if now is None else now
        local = datetime.fromtimestamp(now)
        if self._next_nightly is None:
            self._next_nightly = next_run(local, self.hh, self.mm)
        if self.scorer.model is None and now >= self._next_bootstrap:
            self._next_bootstrap = now + BOOTSTRAP_RETRY_S
            return self.train_now(now)
        if local >= self._next_nightly:
            self._next_nightly = next_run(local, self.hh, self.mm)
            return self.train_now(now)
        return False
