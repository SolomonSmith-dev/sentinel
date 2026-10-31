#!/usr/bin/env python3
"""Rotate EVE by rename/reopen, retain bounded archives, supervise Suricata."""
import logging
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import time

log = logging.getLogger("suricata-retention")
MIB = 1024 * 1024


class Retention:
    def __init__(self, directory, max_bytes=128 * MIB, rotate_bytes=16 * MIB,
                 max_age=86400, interval=3600):
        self.directory = Path(directory)
        self.active = self.directory / "eve.json"
        self.max_bytes, self.rotate_bytes = max_bytes, rotate_bytes
        self.max_age, self.interval = max_age, interval
        self.opened_at = time.time()

    def rotate(self, reopen, *, force=False):
        if not self.active.exists():
            return False
        if not force and self.active.stat().st_size < self.rotate_bytes and time.time() - self.opened_at < self.interval:
            return False
        archive = self.directory / f"eve.json.{time.time_ns():020d}"
        self.active.rename(archive)
        reopen()
        self.opened_at = time.time()
        log.info("rotated EVE; unread records retained for shipper")
        return True

    def prune(self):
        files = sorted(self.directory.glob("eve.json.[0-9]*"))
        total = sum(p.stat().st_size for p in files)
        removed = 0
        for p in files:
            # Do not unlink a file still awaiting the writer's reopen.
            if p == files[-1] and not self.active.exists():
                continue
            size = p.stat().st_size
            if total <= self.max_bytes and time.time() - p.stat().st_mtime <= self.max_age:
                continue
            p.unlink()
            total -= size
            removed += 1
        if removed:
            log.warning("retention evicted %d EVE archives; a lagging shipper may lose unread alerts", removed)
        free = shutil.disk_usage(self.directory).free
        if free < 1024 * MIB:
            log.error("low disk space: less than 1 GiB free on IDS log filesystem")
        return removed


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    retention = Retention("/var/log/suricata")
    retention.rotate(lambda: None, force=True)
    # Hard per-file safety ceiling if a burst outruns the two-second rotation loop.
    # A writer hitting this limit fails visibly and Docker restarts this service.
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * MIB, 64 * MIB))
    child = subprocess.Popen(sys.argv[1:])
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda signum, _frame: child.send_signal(signum))
    # Operational rotation check uses the same path as normal size/time rotation.
    signal.signal(signal.SIGUSR1, lambda *_: retention.rotate(lambda: child.send_signal(signal.SIGHUP), force=True))
    while child.poll() is None:
        retention.rotate(lambda: child.send_signal(signal.SIGHUP))
        retention.prune()
        time.sleep(2)
    log.error("Suricata exited with status %s", child.returncode)
    return child.returncode if child.returncode >= 0 else 128 - child.returncode


if __name__ == "__main__":
    sys.exit(main())
