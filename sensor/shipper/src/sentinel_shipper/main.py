"""`sentinel-shipper` entrypoint: the 30 s loop."""

from __future__ import annotations

import logging
import signal
import sys
import threading
import time

import httpx

from . import __version__, anonymize
from .config import ConfigError, Settings, parse_hhmm
from .eve import EveTailer
from .geo import GeoDb
from .mlcore import Scorer
from .mlmode import ml_enabled
from .pipeline import Pipeline
from .queue import DiskQueue
from .sender import Sender
from .state import State
from .training import Trainer

log = logging.getLogger("sentinel_shipper")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"sentinel-shipper: {exc}", file=sys.stderr)
        return 2

    once = "--once" in (argv if argv is not None else sys.argv[1:])
    log.info("sentinel-shipper %s starting: %r", __version__, settings)  # repr hides token/salt/wan ip

    settings.state_dir.mkdir(parents=True, exist_ok=True)
    state = State(settings.state_dir / "state.db")
    queue = DiskQueue(settings.state_dir)
    geo = GeoDb.load(settings.geo_db)
    oui = anonymize.OuiDb.load(settings.oui_db)
    log.info("geo ranges: %d, OUI prefixes: %d, queued batches: %d", len(geo), len(oui), len(queue))

    model_path = settings.state_dir / "model.joblib"
    ml_on = ml_enabled()
    scorer = Scorer(None)
    if ml_on:
        from .model import AnomalyModel  # lazy: never imported when ML is off

        scorer.model = AnomalyModel.load(model_path)
    if ml_on and scorer.model is None:
        log.info("no model yet: scores are null until one is trained; rules still run")
    hh, mm = parse_hhmm(settings.retrain_at)
    trainer = Trainer(state, scorer, model_path, hh, mm, enabled=ml_on)
    pipeline = Pipeline(
        sensor_id=settings.sensor_id,
        salt=settings.salt,
        windows_dir=settings.windows_dir,
        state=state,
        queue=queue,
        geo=geo,
        oui=oui,
        scorer=scorer,
        eve=EveTailer(settings.eve_path, settings.state_dir / "eve_offset.json"),
    )

    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())

    with httpx.Client(timeout=settings.http_timeout_s,
                      headers={"User-Agent": f"sentinel-shipper/{__version__}"}) as client:
        sender = Sender(client=client, url=settings.ingest_url, token=settings.token,
                        queue=queue, wan_ip=settings.wan_ip)
        while not stop.is_set():
            started = time.monotonic()
            try:
                trainer.maybe_train()
                res = pipeline.tick()
                if res.files or res.alerts:
                    log.info("tick: %d files, %d host windows -> %d windows, %d alerts, %d batch(es)",
                             res.files, res.host_windows, res.windows, res.alerts, res.batches)
                sender.drain()
            except Exception:
                log.exception("tick failed; will retry next interval")
            if once:
                break
            stop.wait(max(0.0, settings.interval_s - (time.monotonic() - started)))
    state.close()
    log.info("stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
