# Sentinel anomaly model

An unsupervised isolation forest scores every 10 second window of every LAN host
on the sensor host. Scores go into the ingest batches (`windows[].score`, max per
60 s bucket), and a score above 0.8 raises an `ml_anomaly` alert. The code lives
in `sensor/shipper/src/sentinel_shipper/model.py`. `ml/train.py` is the offline
harness: it uses the same code to train and evaluate.

## Why an isolation forest

- **No labels.** A home LAN has no ground truth: nobody marks which 10 s
  windows were "attacks". Supervised models are out. The model has to learn
  what normal looks like from the traffic itself.
- **Anomalies are few and different.** An isolation forest builds random trees
  and measures how few random splits it takes to separate a point from the
  rest. Rare, extreme points get isolated near the root. That matches the
  target: scans and floods are rare and sit far from normal traffic on at least
  one axis.
- **Cheap.** Training on 100k rows takes seconds and scoring is a few tree
  walks per window, which matters on a 2-core Core 2 Duo that also runs other
  services. No GPU, no daemon, one joblib file.
- **Rules already cover the known patterns.** The deterministic rules
  (flood, port_scan, geo, new device) catch the patterns we can name. The
  model is the safety net for unusual combinations nobody wrote a rule for.

## Features (schema version 1)

One row per host per 10 s window, straight from the capture's counters:

| feature          | source                       | transform |
|------------------|------------------------------|-----------|
| `bytes_in`       | `bytes_in`                   | log1p     |
| `bytes_out`      | `bytes_out`                  | log1p     |
| `pkts`           | `pkts_in + pkts_out`         | log1p     |
| `distinct_dests` | `distinct_dests`             | log1p     |
| `distinct_ports` | `distinct_ports_out`         | log1p     |
| `syn_ratio`      | `syn_out / pkts_out` (0 if no outbound packets) | none, already in [0, 1] |

**Why log1p.** The counts are heavy-tailed and span about six orders of
magnitude: an idle smart plug sends 2 packets in 10 s, a TV streaming 4K
receives 30,000. An isolation tree picks each split uniformly between a
feature's min and max. On a raw scale almost every split lands in the empty
space between ordinary hosts and the single largest value, so differences
between ordinary hosts carry no weight. On a log scale the splits are
proportional (10 to 100 counts as much as 10k to 100k), which matches how
traffic actually varies. `log1p` rather than `log` keeps zero at zero, and idle
windows are full of zeros.

The feature list and a schema version are saved with the model. A model with a
different schema is ignored at load time, so the shipper never scores with
mismatched columns.

## Calibration: from `score_samples` to [0, 1]

`IsolationForest.score_samples` returns the negated anomaly score from the
original paper: around -0.4 to -0.5 for typical points, toward -1 for outliers.
Its scale moves every time the model is retrained. The API wants a stable
number in [0, 1] where higher means more anomalous, so the shipper:

1. flips the sign: `raw = -score_samples(x)`, so higher means more anomalous;
2. records two quantiles of `raw` on the training data: the median and the
   99.9th percentile;
3. maps linearly so the median goes to 0.5 and the 99.9th percentile goes to 0.8,
   extrapolates past both anchors, and clips to [0, 1].

A score above 0.8 means "more isolated than 99.9% of the windows this model was
trained on". That reading holds across retrains, so the alert threshold does
not need retuning when the model changes. By construction about 0.1% of
training-like windows cross it. The rules engine's 5 minute per-device debounce
caps how often that turns into an alert.

## Training and retraining

- Every scored window's raw features go into a SQLite table in the state dir.
  Rows older than 7 days are pruned, so the store is a rolling week.
- **Nightly** at 03:30 local time (`SENTINEL_RETRAIN_AT`), the shipper trains on
  a uniform random sample of up to 100k rows from the trailing 7 days and
  replaces the model atomically.
- **Bootstrap:** while no model exists, the shipper tries to train at startup
  and then hourly, once the store spans at least 2 hours. Until then `score` is
  `null` and only the rules run.
- Hyperparameters: 200 trees, 256 samples per tree, `contamination="auto"`
  (unused, since we calibrate ourselves), fixed `random_state`.

## Offline evaluation (`ml/train.py`)

```
pip install -e sensor/shipper
python ml/train.py                                         # synthetic benign data
python ml/train.py --sqlite /var/lib/sentinel/state/state.db --save model.joblib
python ml/train.py --features rows.csv
```

The script holds out 20% of the benign rows, injects synthetic scan-like rows
(many ports, mostly SYNs, small packets) and flood-like rows (20k to 300k packets
in 10 s to one or two destinations, either SYN floods or UDP floods), and
reports the score distribution and precision/recall at 0.8.

Output on **synthetic** benign traffic (`python ml/train.py`, seed 7, 50k rows):

```
calibration        : raw p50=0.4863 -> 0.5, raw p99.9=0.6548 -> 0.8
held-out benign    p50 0.500   p99 0.730   p99.9 0.796
injected scan      p1 0.794    p50 0.825
injected flood     p1 0.695    p50 0.770   p75 0.884
at threshold > 0.8
  benign false positive rate : 8/10000 = 0.0800%
  recall scan                : 479/500 = 95.80%
  recall flood               : 247/500 = 49.40%
  precision (this mix)       : 726/734 = 98.91%
```

How to read it:

- These are synthetic numbers. The benign generator is a guess at a home LAN,
  and the anomalies come from the same author's idea of a scan and a flood. The
  run shows that the pipeline works and how the score behaves. It is not a
  measured detection rate on real traffic. Run it with `--sqlite` against a
  real feature store before trusting any number.
- Scans separate well because they are extreme on `distinct_ports` and
  `syn_ratio` at the same time.
- About half the floods score under 0.8. These are mostly UDP-style floods
  (`syn_ratio` near 0), which look like a very large streaming host with few
  destinations. The model gives them a high score, but not high enough to beat
  a threshold anchored on the 99.9th percentile. Floods like these are what the
  deterministic flood rule is for: more than 20,000 packets to one destination,
  or more than 500 SYNs, in 10 s. The model is not the main flood detector.
- Precision depends on the ratio of anomalies to benign rows in the test set
  (1:10 here). On a real LAN anomalies are far rarer, so real precision would be
  lower. The false positive rate (0.08% of benign windows) is the number that
  carries over.

## Limits

- **Poisoning.** The model learns "normal" from the last 7 days. A compromised
  device that misbehaves for a week becomes normal. The rules do not drift this
  way.
- **No per-device baseline.** One model covers all hosts. A window that is
  normal for the TV but strange for the thermostat scores as normal. Per-device
  or per-vendor models would fix this but need more data per device.
- **10 s windows only.** Slow scans spread over minutes never look extreme in a
  single window.
- **Counts, not content.** The capture only gives packet counters, so the model
  cannot see payloads, DNS names or TLS fingerprints. Suricata covers content.
- **Cold start.** No scores for the first 2 hours. The first model is trained on
  a thin, possibly unrepresentative sample until the nightly retrain has a full
  week.
