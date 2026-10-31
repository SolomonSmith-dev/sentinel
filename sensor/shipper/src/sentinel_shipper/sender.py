"""POST queued batches to /api/ingest with retries.

- Body: compact JSON, gzip-compressed. `Idempotency-Key` is the sha256 hex of
  the *uncompressed* bytes. `sent_at` and `queue_depth` are stamped on the first
  attempt and saved back to the queue file, so every retry sends identical
  bytes and the Worker can recognise a retry whose first response was lost.
- 200 `ok` or `duplicate`: done, remove from queue.
- 429 / 5xx / network error: exponential backoff with full jitter
  (delay = uniform(0, min(cap, base * 2**attempt))), honouring Retry-After.
  The loop does not sleep on this: `drain()` just returns and tries again on a
  later tick once the backoff has elapsed.
- 400 pii_rejected / checksum_mismatch / too_many_items, 413: the batch can
  never succeed; quarantine it. 401: keep it and back off (a fixed token
  should let it through).
- Privacy guard: the serialized body is scanned before every send; a match
  quarantines the batch and nothing is sent.
The token is only ever placed in the Authorization header, never logged.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

from . import privacy
from .queue import DiskQueue, Item

log = logging.getLogger(__name__)

BACKOFF_BASE_S = 2.0
BACKOFF_CAP_S = 300.0
RETRYABLE = {408, 425, 429, 500, 502, 503, 504}


def serialize(body: dict[str, Any]) -> bytes:
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def idempotency_key(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass
class Sender:
    client: httpx.Client
    url: str
    token: str = field(repr=False)
    queue: DiskQueue
    wan_ip: str | None = field(default=None, repr=False)
    clock: Callable[[], float] = time.time
    rng: random.Random = field(default_factory=random.Random)
    attempt: int = 0
    next_attempt_at: float = 0.0
    sent_ok: int = 0

    def backoff(self, retry_after: float | None = None) -> float:
        delay = self.rng.uniform(0, min(BACKOFF_CAP_S, BACKOFF_BASE_S * (2 ** min(self.attempt, 10))))
        if retry_after is not None:
            delay = max(delay, min(retry_after, BACKOFF_CAP_S))
        self.attempt += 1
        self.next_attempt_at = self.clock() + delay
        return delay

    def drain(self, max_batches: int = 20) -> int:
        """Send queued batches in order until one fails or the queue is empty."""
        if self.clock() < self.next_attempt_at:
            return 0
        sent = 0
        for item in self.queue.items()[:max_batches]:
            outcome = self._send_one(item)
            if outcome == "retry":
                break
            if outcome == "ok":
                sent += 1
        return sent

    def _finalize(self, item: Item) -> dict[str, Any]:
        body = item.load()
        if "sent_at" not in body:
            body["sent_at"] = int(self.clock())
            body["queue_depth"] = max(len(self.queue) - 1, 0)
            # keep contract field order: sensor_id, sent_at, queue_depth, ...
            ordered = {"sensor_id": body.pop("sensor_id"), "sent_at": body.pop("sent_at"),
                       "queue_depth": body.pop("queue_depth")}
            ordered.update(body)
            body = ordered
            self.queue.update(item, body)
        return body

    def _send_one(self, item: Item) -> str:
        try:
            body = self._finalize(item)
        except (OSError, ValueError) as exc:
            self.queue.quarantine(item, f"unreadable queue file ({type(exc).__name__})")
            return "dropped"
        raw = serialize(body)
        try:
            privacy.check(raw, self.wan_ip)
        except privacy.PrivacyViolation as exc:
            self.queue.quarantine(item, f"privacy guard: {', '.join(exc.kinds)}")
            return "dropped"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "Idempotency-Key": idempotency_key(raw),
        }
        try:
            resp = self.client.post(self.url, content=gzip.compress(raw), headers=headers)
        except httpx.HTTPError as exc:
            delay = self.backoff()
            log.warning("ingest failed (%s); retry in %.1f s", type(exc).__name__, delay)
            return "retry"

        status, code = resp.status_code, _error_code(resp)
        if status in {301, 302, 303, 307, 308, 403} or (status == 200 and code not in {"ok", "duplicate"}):
            delay = self.backoff()
            log.error("ingest authentication/proxy response %d; preserving batch, retry in %.1f s", status, delay)
            return "retry"
        if status == 200:
            self.queue.remove(item)
            self.attempt = 0
            self.next_attempt_at = 0.0
            self.sent_ok += 1
            log.info("ingest %s: %s windows, %s alerts", code or "ok",
                     len(body.get("windows", [])), len(body.get("alerts", [])))
            return "ok"
        if status in RETRYABLE:
            delay = self.backoff(_retry_after(resp))
            log.warning("ingest %d %s; retry in %.1f s", status, code, delay)
            return "retry"
        if status == 401:
            delay = self.backoff()
            log.error("ingest 401 unauthorized: check SENTINEL_TOKEN; retry in %.1f s", delay)
            return "retry"
        self.queue.quarantine(item, f"rejected by API: {status} {code}")
        return "dropped"


def _error_code(resp: httpx.Response) -> str:
    try:
        data = resp.json()
    except ValueError:
        return ""
    if isinstance(data, dict):
        return str(data.get("error") or data.get("status") or "")
    return ""


def _retry_after(resp: httpx.Response) -> float | None:
    value = resp.headers.get("Retry-After")
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None
