# Sentinel QA findings

Date: 2026-10-24. Reviewer: qa-reviewer (read-only for code). Commit under test: `da61bcf`.
Everything below was run on this Mac against a local `wrangler dev` Worker with local D1. No requests were sent to production.

## 1. Suite results

| Suite | Command | Result |
|---|---|---|
| API typecheck | `cd api && npm run typecheck` | pass (tsc, no errors) |
| API tests | `cd api && npm test` | 40 passed, 0 failed (3 files) |
| Dashboard build | `cd dashboard && npm run build` | pass (601 modules; JS 595.6 kB, 178.4 kB gzip) |
| Capture build | `cmake ... -DSENTINEL_WERROR=ON` + `cmake --build -j` | pass, no warnings under -Werror |
| Capture tests | `ctest` | 4 of 4 passed (unit_tests, 3 fixture replays) |
| Shipper | `.venv/bin/pytest -q` | 123 passed, 0 failed |
| shellcheck | `shellcheck deploy-sensor.sh` | clean, exit 0 |
| Deploy dry run | `bash deploy-sensor.sh --dry-run` | exit 1 (see F4). Printed the expected "interface eth0 not present on this host (ok for a dry run)", then failed at compose validation |
| Dependency audit | `npm audit --omit=dev` in api and dashboard | 0 vulnerabilities each |
| Secret scan | `gitleaks detect --no-banner` | 7 commits scanned, no leaks. `.env` and `api/.dev.vars` are gitignored (`git check-ignore` confirmed) |

## 2. Threat checklist: `POST /api/ingest` (local Worker, port 8798; kill switch on 8799)

| Case | Expected | Actual | Result |
|---|---|---|---|
| No Authorization header | 401 | 401 unauthorized | pass |
| Wrong token, same length | 401 | 401 | pass |
| Token of different length | 401 | 401 | pass |
| Empty bearer value | 401 | 401 | pass |
| Correct token, Idempotency-Key not hex | 400 | 400 missing_idempotency_key | pass |
| Correct token, key is valid hex but wrong sha | 400 | 400 checksum_mismatch | pass |
| Idempotency-Key header absent | 400 | 400 missing_idempotency_key | pass |
| Valid gzip batch | 200 | 200 ok | pass |
| Replay of same body (sent plain) | 200 duplicate | 200 duplicate | pass |
| Raw body 300 KB | 413 | 413 too_large | pass |
| Gzip bomb, 2 MB of zeros (about 2 KB sent) | 413 | 413 too_large | pass |
| Gzip bomb, 50 MB of zeros | 413 | 413 too_large | pass |
| Gzip magic bytes followed by garbage, Content-Encoding gzip | 400 | 400 invalid_body | pass |
| 501 windows | 400 too_many_items | 400 too_many_items | pass |
| 500 windows (boundary) | 200 | 200 ok | pass |
| 501 alerts | 400 | 400 too_many_items | pass |
| 201 devices | 400 | 400 too_many_items | pass |
| IPv4 in a detail string | 400 pii_rejected | 400 pii_rejected | pass |
| MAC (colon) in vendor string | 400 pii_rejected | 400 pii_rejected | pass |
| MAC (dash) in vendor string | 400 pii_rejected | 400 pii_rejected | pass |
| JSON-escaped IPv4 (`192.168.1.1`) | 400 pii_rejected | 400 pii_rejected | pass |
| Partially escaped IPv4 (`192.168.1.1`) | 400 pii_rejected | 400 pii_rejected | pass |
| IPv6 `2001:db8::1`, `fe80::1`, full 8-group form, `::1`, `::ffff:1.2.3.4` | 400 pii_rejected | 400 pii_rejected for all five | pass |
| Country key `us`, `USA`, `U1`, empty, `US ` | 400 | 400 invalid_body for all | pass |
| Country key `??` and `U?` | 200 | 200 | pass |
| Severity `urgent` | 400 | 400 invalid_body | pass |
| Alert type `bogus` | 400 | 400 invalid_body | pass |
| Detail 2049 bytes ASCII | 400 | 400 invalid_body | pass |
| Detail 2048 bytes ASCII (boundary) | 200 | 200 | pass |
| Detail given as an array | 400 | 400 | pass |
| Detail of 1000 emoji (about 4 KB UTF-8) | 400 per contract ("2 KB serialized") | 200 ok | FAIL (F5) |
| Window and alert ts one year in the future | 200, clamped to received_at + 300 | 200; D1 shows window ts - received_at = 252 (bucket-aligned), alert and device last_seen = 300 | pass |
| Window ts = 0 | not specified | 200, stored with ts 0 | note (F7) |
| device_hash `dev-ZZZZZZ` | 400 | 400 | pass |
| ts not 60-aligned | 400 | 400 | pass |
| Body not JSON / not UTF-8 | 400 | 400 / 400 | pass |
| `GET /api/ingest` | 404 | 404 | pass |
| Version string `v2.0.1.3` in a Suricata signature | 200 (not an address) | 400 pii_rejected | FAIL (F3) |
| Hostname `johns-macbook.local` in a detail value | not covered by contract | 200 ok, stored | note (F6) |
| Burst of 90 unauthenticated POSTs in one minute | 401 then 429 | 86 x 401, 4 x 429 (limiter works) | pass |
| `INGEST_ENABLED=false`, valid auth | 503 | 503 ingest_disabled | pass |
| `INGEST_ENABLED=false`, no auth | 503 | 503 ingest_disabled (kill switch is checked before auth) | pass |

Cleanup: both dev servers killed (ports 8798 and 8799 verified free, no wrangler or workerd left). Local D1 cleaned with the specified command; I also deleted `ingest_log` rows (they were all created by vitest and this run). Final counts: 0 non-seed alerts, windows, devices, idempotency and ingest_log rows. Before cleanup, local D1 already held non-seed rows from the vitest run (9 alerts, 9 windows, 6 devices, 3 idempotency keys); those were deleted too.

## 3. Findings, ranked

### F1 (High): every unauthenticated or rejected request costs D1 writes; the rate limiter does not bound them
- Where: `api/src/ingest.ts:85-110` (`logAttempt`, INSERT at line 103), called from `fail()` at line 132, including the 429 path at line 140. Indexes: `api/migrations/0001_init.sql:70,72` (two on `ingest_log`).
- What is wrong: `fail()` writes an `ingest_log` row for 401, 413, 429 and 503. Rate-limit and auth failures happen before any trust is established, so anyone can make the Worker write to D1. The limiter caps successful processing, not logging: 429 responses are logged too, so a single IP has no write cap at all, and many IPs each get 60 per minute. docs/api.md says each index entry counts as a row written, so each logged request costs about 3 row-writes (table plus two indexes). By that accounting about 33k junk requests exhaust the 100k/day free-tier write budget, after which real ingest returns 503 storage_unavailable and the seed cron stops. The failure counts shown on the public `/api/metrics` can also be inflated.
- Proof: against the local Worker, 90 POSTs with no token produced 86 x 401 and 4 x 429, and `ingest_log` grew by exactly 90 rows (61 to 151), 429s included. The 3 row-writes per request and the 33k figure are arithmetic from the contract's own accounting, not measured. Production was not probed.
- Fix: do not insert into `ingest_log` for failures before auth succeeds (401, 429, 503 disabled). Count them with Workers Logs (already enabled in `wrangler.jsonc`) or log only authenticated attempts. Add a Cloudflare WAF rate-limiting rule on `/api/ingest` for the distributed case.

### F2 (Medium): public read endpoints hit D1 on every request, and the cache key accepts arbitrary query strings
- Where: `api/src/reads.ts:101-147` (`metrics`, with `SELECT COUNT(*) FROM windows` at line 113), `reads.ts:24` (`flows`), `reads.ts:40` (`alerts`), none cached; `cachedJson` at `reads.ts:12-22` keys on the full URL including unknown params.
- What is wrong: `/api/metrics`, `/api/flows` and `/api/alerts` are unauthenticated, uncached at the edge (the Worker runs first for `/api/*`), and `metrics` scans the whole `windows` table. D1 bills rows scanned. `/api/top` and `/api/devices` are cached, but `?x=<random>` creates a new cache key per request and forces a recompute.
- Proof: local `windows` has 12,033 rows (seed only), and the `metrics` query counts all of them each call. Against the 5M rows-read/day free tier that is roughly 400 calls on seed data alone, and far fewer once real data accumulates (the contract budgets about 43k rows/day, so about 300k rows after a week, about 16 calls). This is an estimate from measured table size; wrangler local did not report `rows_read`, and production was not tested.
- Fix: wrap `metrics`, `flows` and `alerts` in `cachedJson`, and build the cache key from an allowlist of known params only. Replace the three `COUNT(*)` scans with a counter maintained by the cron.

### F3 (Medium): shipper and Worker privacy regexes disagree; a benign signature quarantines a whole batch
- Where: `sensor/shipper/src/sentinel_shipper/privacy.py:11-12` (`\b` boundaries) versus `api/src/ingest.ts:15-18` (lookbehind on digits or hex). `redact()` (`privacy.py:45`) uses the shipper's weaker patterns on Suricata signature and category (`eve.py:88,90`).
- What is wrong: text such as `v2.0.1.3` has no `\b` before the 2, so the shipper neither redacts nor blocks it, but the Worker matches `2.0.1.3` as IPv4 and returns 400 pii_rejected. `sender.py` treats that as unrecoverable and quarantines the entire batch (up to 500 windows and all their alerts). A version number in one ET signature loses a minute or more of telemetry. No address leaks; this is data loss and a silent gap.
- Proof: a real Worker returned `400 pii_rejected` for an alert with signature "ET TROJAN Foo v2.0.1.3 beacon". `privacy.violations()` on the same string returned `[]`. A Python port of the Worker regexes also diverges on `Foo_1.2.3.4`, `build1.2.3.4`, `g1.2.3.4h`, `sid:1:2:3` and `xa4:83:e7:12:34:56` (port only; those were not sent to the Worker).
- Fix: use identical patterns on both sides (copy the Worker's lookaround regexes into `privacy.py`) and add a shared fixture of strings both must classify the same way. Also make `redact()` drop the digits of anything the Worker would match.

### F4 (Low): `deploy-sensor.sh --dry-run` fails on a fresh checkout
- Where: `deploy-sensor.sh:45,89` and `sensor/docker-compose.yml:77-78` (`env_file: ../.env`).
- What is wrong: dry run substitutes `.env.example` for `--env-file`, but the shipper service's `env_file: ../.env` is mandatory, so `docker compose config` fails when `.env` does not exist yet. A dry run cannot validate a fresh host, which is the case it exists for.
- Proof: ran `bash deploy-sensor.sh --dry-run`; output ended with "env file .../sentinel/.env not found", exit 1. (Run on macOS; the failing line is compose validation, not the interface check.)
- Fix: use `env_file: [{path: ../.env, required: false}]` (Compose 2.24+), or have dry run create a temp `.env` copy and point compose at it.

### F5 (Low): the 2 KB `detail` cap counts UTF-16 code units, not bytes
- Where: `api/src/ingest.ts:55` (`JSON.stringify(d).length <= 2048`).
- What is wrong: the contract says 2 KB serialized. Emoji count as 2 units for 4 bytes, so about 4 KB of UTF-8 is accepted. Bounded by the 256 KB body cap, so impact is small storage bloat from a token holder.
- Proof: 1000 emoji in `detail.k` returned 200 ok.
- Fix: compare `new TextEncoder().encode(JSON.stringify(d)).length`.

### F6 (Low): no guard for hostnames in the ingest body
- Where: `api/src/ingest.ts:11-28` (`containsPii` covers IPv4, MAC, IPv6 only).
- What is wrong: the README says no hostname leaves the house, but nothing enforces it at the Worker. The shipper code never builds a hostname (grep of `sensor/shipper/src` found none), so today it holds; free-text fields (`detail`, `vendor`) from a future code change would pass silently.
- Proof: a `detail` value of `johns-macbook.local` returned 200 and was stored.
- Fix: restrict `detail` to a per-type schema (keys and value types), and cap `vendor` to a known-vendor pattern. This also removes the free-form text surface.

### F7 (Low): ancient timestamps accepted
- Where: `api/src/ingest.ts:293-294` (clamp is upper-bound only).
- What is wrong: `ts` can be any past value. `ts = 0` is stored. Nightly prune removes it, but until then it sits in the 7-day tables and skews `first_seen` (devices keep the earliest).
- Proof: window with `ts: 0` returned 200; D1 row stored with ts 0.
- Fix: reject or clamp `ts < received_at - 7 days`.

### F8 (Low): no security headers on the dashboard or API
- Where: `api/wrangler.jsonc` (assets), no `_headers` file under `dashboard/public/`.
- What is wrong: no CSP, `X-Content-Type-Options`, `Referrer-Policy` or `frame-ancestors`. React escapes all text, so there is no known injection path, but nothing limits damage if one appears.
- Proof: `curl -I` on the local Worker for `/` and `/api/metrics` showed none of these headers. Production headers were not checked.
- Fix: add `dashboard/public/_headers` with a CSP (`default-src 'self'`) and the other three.

### F9 (Low): compose hardening not applied
- Where: `sensor/docker-compose.yml:33,61,77`.
- What is wrong: `sentinel-capture` adds NET_ADMIN, but the image only grants `cap_net_raw+ep` (`sensor/capture/Dockerfile`) and libpcap capture needs only NET_RAW. No service sets `cap_drop: [ALL]`, `read_only: true` or `security_opt: [no-new-privileges]`. The shipper (the only service that talks to the internet) runs non-root but with default capabilities.
- Proof: read of the compose file and Dockerfiles only; not exercised at runtime.
- Fix: drop NET_ADMIN from capture; add `cap_drop: [ALL]` plus `read_only: true` and `no-new-privileges` to the shipper. (Do not set no-new-privileges on capture, it blocks the file capability.) Suricata's NET_ADMIN, NET_RAW and SYS_NICE match its published requirements.

### Checked, no finding
- IP/MAC/hostname paths to the cloud: the capture-to-shipper file is local; the shipper emits only `device_hash`, country codes, counts and (redacted) signature, sid, category. Alert details in `rules.py` carry counts and country codes. Eve source and destination IPs are resolved to a hash and dropped (`eve.py:158`). Logs: `main.py:37` prints settings via a repr that hides token, salt and WAN IP; nothing logs window contents. The sender runs the privacy guard on the final bytes before every send.
- XSS: `grep` for `dangerouslySetInnerHTML`, `innerHTML`, `eval`, `new Function`, `document.write` across `dashboard/src` found nothing. Alert `detail` is rendered as a React text node (`AlertFeed.tsx:64` via `summarizeDetail`), so HTML in a signature is displayed inert. The only `href` is the fixed repo URL.
- Read endpoints: all SQL uses bound parameters; `limit` and `minutes` are clamped; errors return generic messages. They return hashes, vendor, byte counts, sensor_id, queue_depth, last_seen and row counts. That is by design, but vendor plus per-device byte timing and sensor liveness allow household presence inference (informational).
- Auth: constant-time compare via SHA-256 digests; kill switch checked before auth; body caps enforced while streaming (no unbounded buffering of a gzip bomb).

## 4. Known limitations (not re-reported as findings)

- Capture per-window caps are first-come: an attacker spoofing more than 4096 MACs in 10 s can crowd out real hosts; overflow is only logged.
- `eve.json` is never rotated.
- numpy is pinned to 2.3 for a Core 2 Duo host, untested on that CPU.
- Seed device hashes all start with `dev-5e0` (fix parked on branch `seed-hash-refresh`).
