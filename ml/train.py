#!/usr/bin/env python3
"""Offline trainer and evaluator for the Sentinel isolation-forest model.

Uses the exact feature transform, model and calibration the shipper runs
(`sentinel_shipper.model`), so what you measure here is what ships.

Data sources (pick one):
  --features FILE.csv   columns: bytes_in,bytes_out,pkts,distinct_dests,distinct_ports,syn_ratio
  --sqlite state.db     the shipper's own feature store (<state dir>/state.db)
  (neither)             synthetic home-LAN traffic, clearly labelled as such

Evaluation: hold out 20% of the benign rows, inject synthetic scan-like and
flood-like rows, score everything and report precision / recall at the 0.8
alert threshold. Injected anomalies are synthetic: the numbers say how well
the model separates *these* patterns from *this* benign data, nothing more.

    pip install -e sensor/shipper
    python ml/train.py                       # synthetic
    python ml/train.py --sqlite /var/lib/sentinel/state/state.db --save model.joblib
"""

from __future__ import annotations

import argparse
import csv
import sqlite3
import sys
from pathlib import Path

import numpy as np

from sentinel_shipper.model import ALERT_THRESHOLD, FEATURES, AnomalyModel


def synthetic_benign(n: int, rng: np.random.Generator) -> np.ndarray:
    """Three host profiles seen on a home LAN, with lognormal noise.

    idle IoT (50%): a handful of packets to 1-2 cloud endpoints
    interactive (35%): browsing / apps, tens to hundreds of packets, many dests
    streaming (15%): TV / video, thousands of packets, big inbound bytes
    """
    kind = rng.choice(3, size=n, p=[0.5, 0.35, 0.15])
    pkts = np.select([kind == 0, kind == 1, kind == 2],
                     [rng.lognormal(2.0, 0.6, n), rng.lognormal(5.0, 0.8, n), rng.lognormal(7.5, 0.4, n)])
    bytes_in = pkts * np.where(kind == 2, rng.normal(1300, 100, n), rng.normal(600, 150, n)).clip(60)
    bytes_out = pkts * rng.normal(120, 30, n).clip(60)
    dests = np.where(kind == 0, rng.integers(1, 3, n), rng.integers(2, 25, n))
    ports = np.minimum(dests, rng.integers(1, 5, n))
    syn_ratio = rng.beta(1, 40, n)
    return np.column_stack([bytes_in, bytes_out, pkts, dests, ports, syn_ratio])


def synthetic_scans(n: int, rng: np.random.Generator) -> np.ndarray:
    """A host probing many ports: small packets, mostly SYNs, 25-1000 ports."""
    pkts = rng.integers(30, 2000, n).astype(float)
    ports = np.minimum(pkts, rng.integers(25, 1000, n))
    return np.column_stack([
        pkts * rng.uniform(40, 70, n),   # bytes_in: RSTs / SYN-ACKs
        pkts * rng.uniform(55, 70, n),   # bytes_out: bare SYNs
        pkts * rng.uniform(1.0, 2.0, n),
        rng.integers(1, 30, n),
        ports,
        rng.uniform(0.6, 1.0, n),
    ])


def synthetic_floods(n: int, rng: np.random.Generator) -> np.ndarray:
    """A host blasting one target: 20k-300k packets in 10 s, few dests."""
    pkts = rng.uniform(20_000, 300_000, n)
    return np.column_stack([
        pkts * rng.uniform(0, 5, n),
        pkts * rng.uniform(60, 1400, n),
        pkts,
        rng.integers(1, 3, n),
        rng.integers(1, 3, n),
        rng.choice([0.0, 0.99], n) + rng.uniform(0, 0.01, n),  # UDP flood or SYN flood
    ])


def load_csv(path: Path) -> np.ndarray:
    with path.open(newline="") as fh:
        reader = csv.DictReader(fh)
        missing = [f for f in FEATURES if f not in (reader.fieldnames or [])]
        if missing:
            sys.exit(f"{path}: missing columns {missing}")
        return np.array([[float(row[f]) for f in FEATURES] for row in reader])


def load_sqlite(path: Path) -> np.ndarray:
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    rows = db.execute(f"SELECT {', '.join(FEATURES)} FROM features").fetchall()
    db.close()
    return np.array(rows, dtype=float).reshape(-1, len(FEATURES))


def pct_table(name: str, scores: np.ndarray) -> str:
    qs = [1, 25, 50, 75, 90, 99, 99.9]
    vals = np.percentile(scores, qs)
    head = " ".join(f"p{q:<5}" for q in qs)
    return f"{name:<18} n={len(scores):<7} {head}\n{'':<27} " + " ".join(f"{v:<6.3f}" for v in vals)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--features", type=Path, help="CSV of feature rows")
    src.add_argument("--sqlite", type=Path, help="shipper state.db")
    ap.add_argument("--synthetic-rows", type=int, default=50_000)
    ap.add_argument("--inject", type=int, default=500, help="synthetic anomalies of each kind")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--save", type=Path, help="write the trained model (joblib) here")
    args = ap.parse_args()

    rng = np.random.default_rng(args.seed)
    if args.features:
        data, source = load_csv(args.features), str(args.features)
    elif args.sqlite:
        data, source = load_sqlite(args.sqlite), str(args.sqlite)
    else:
        data, source = synthetic_benign(args.synthetic_rows, rng), "SYNTHETIC benign traffic"
    if len(data) < 500:
        sys.exit(f"only {len(data)} rows; need at least 500 to train and hold out")

    idx = rng.permutation(len(data))
    cut = int(len(data) * 0.8)
    train, test = data[idx[:cut]], data[idx[cut:]]
    model = AnomalyModel.train(train, random_state=args.seed)

    scans = synthetic_scans(args.inject, rng)
    floods = synthetic_floods(args.inject, rng)
    s_train, s_test = model.score(train), model.score(test)
    s_scan, s_flood = model.score(scans), model.score(floods)

    print(f"data source        : {source}")
    print(f"rows               : train={len(train)} held-out benign={len(test)}"
          f" injected scan={len(scans)} flood={len(floods)} (synthetic)")
    print(f"calibration        : raw p50={model.calibration.low:.4f} -> 0.5,"
          f" raw p99.9={model.calibration.high:.4f} -> 0.8")
    print()
    print("calibrated score distribution")
    for name, s in (("train", s_train), ("held-out benign", s_test),
                    ("injected scan", s_scan), ("injected flood", s_flood)):
        print(pct_table(name, s))
    print()

    t = ALERT_THRESHOLD
    fp = int(np.sum(s_test > t))
    tp_scan, tp_flood = int(np.sum(s_scan > t)), int(np.sum(s_flood > t))
    tp = tp_scan + tp_flood
    n_anom = len(scans) + len(floods)
    precision = tp / (tp + fp) if tp + fp else float("nan")
    print(f"at threshold > {t}")
    print(f"  benign false positive rate : {fp}/{len(test)} = {fp / len(test):.4%}")
    print(f"  recall scan                : {tp_scan}/{len(scans)} = {tp_scan / len(scans):.2%}")
    print(f"  recall flood               : {tp_flood}/{len(floods)} = {tp_flood / len(floods):.2%}")
    print(f"  recall overall             : {tp}/{n_anom} = {tp / n_anom:.2%}")
    print(f"  precision (this mix)       : {tp}/{tp + fp} = {precision:.2%}")
    print("  note: precision depends on the anomaly:benign ratio of this test set"
          f" ({n_anom}:{len(test)}), which is far richer in anomalies than a real LAN.")

    if args.save:
        model.save(args.save)
        print(f"\nsaved model to {args.save}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
