# Sentinel security audit

Audited baseline: `58267e0`, 2026-10-31. Repository code/configuration review, local reproductions, dependency advisory checks and Git history secret scan. No production mutation, traffic flood, exploitation, credential rotation, or deployment performed. Runtime host settings, external WAF rules, container OS packages and the complete Suricata dependency tree were not independently audited. This is not a penetration-test certification.

## Findings

### S1 [MED] Rejected private sensor identifiers persist in cloud logs

Location: `api/src/ingest.ts:241`, with sinks at lines 123 and 134.

The handler copies the parsed `sensor_id` into attempt metadata before the decoded-content privacy check. JSON Unicode escapes bypass the initial raw-text check. The later check rejects the request, but `fail()` writes the decoded identifier to console logs and D1 `ingest_log` anyway. Requires a valid ingest token or a buggy authenticated sensor. This is a privacy-boundary failure, not an unauthenticated database read.

Reproduced locally with synthetic `sensor_id` `192.0.2.1`, dots encoded as `\u002e`, valid test authentication and the correct body hash. Response: 400 `pii_rejected`; console and D1 both contained the decoded address. Existing rejection tests check telemetry tables, not rejection-log contents.

Fix: populate attempt identifiers only after privacy and schema validation. Leave identifiers null for rejected bodies. Add regression assertions covering console output and `ingest_log`, including escaped identifiers and item-count failures.

### S2 [MED] Public reads can bypass cache reuse through valid parameters

Location: `api/src/reads.ts:19-29`, `api/src/reads.ts:57-65`; routes in `api/src/index.ts:17-21`.

`/api/alerts` includes every distinct integer `since` value in the cache key. An unauthenticated caller can vary this supported parameter on each request and force fresh D1 reads. The application only rate-limits ingestion. Normalizing unknown parameters does not constrain this legitimate parameter space. Repeated database reads can consume quota or increase cost and impair availability. External Cloudflare protections, if configured separately, were not inspected.

Reproduced locally: requests with `limit=50&since=12341` and `limit=50&since=12342` both returned 200 and created separate cache entries. Code inspection confirms each miss invokes the database handler. No load test was performed, and the request volume needed to exhaust production quotas was not measured.

Fix: add read-route rate limits and a shared cache of recent alert rows, applying the cursor filter after cache retrieval. Bound lookback and supported limits. Test that varied cursors cannot cause unlimited database work; avoid rounding cursors in ways that silently drop alerts.

### S3 [MED] IDS alert storage has no retention bound

Location: `sensor/suricata/sentinel.yaml:27-33`, `sensor/docker-compose.yml:58-60`.

Suricata appends alerts to one `eve.json` in a persistent Docker volume. The repository supplies no rotation or deletion policy. Docker's `json-file` limits apply to container stdout/stderr, not this file. Sustained alert-triggering traffic visible to the sensor can grow this volume until the host filesystem fills, disrupting this sensor and other workloads sharing the disk. The file also retains raw local network metadata indefinitely. This was already listed as a limitation in `docs/qa-findings.md`; it remains unresolved.

Fix: implement size/time rotation with bounded total retention and a disk-space alert. Coordinate rotation with the shipper's inode/offset handling so unread alerts are not silently discarded. Test rotation while the reader is behind. No disk-fill experiment was run.

### S4 [MED deployment risk; HIGH upstream advisories] Vulnerable development dependencies

Location: `api/package-lock.json:63` and `api/package-lock.json:2453`; direct pins in `api/package.json`.

Live `npm audit` reported five affected package entries: three high and two moderate, including transitive Undici and a nested Zod under the Cloudflare test plugin. These counts include dependency ancestors, not five independent exploitable defects. The affected packages are development tooling; the application's Zod 4.6.7 is outside the reported vulnerable range. No deployed Worker exploit was established.

The [Undici maintainer advisory](https://github.com/nodejs/undici/security/advisories/GHSA-xjj6-f33q-929c) describes a process crash caused by a malicious HTTP response; the affected 7.x range is below 7.30.1. Other reported Undici advisories concern TLS validation, redirects and buffering. npm also reported [Zod constrained-collection memory exhaustion](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5) for versions below 4.6.6.

Fix: update the Cloudflare test plugin and Wrangler together, regenerate the lockfile, rerun audit, typecheck and Worker tests. npm suggests plugin 1.4.11; verify the resulting dependency tree rather than assuming that one version change resolves all advisories. Do not run a blind forced dependency upgrade.

### S5 [LOW] Configuration allows sending the bearer token over HTTP

Location: `sensor/shipper/src/sentinel_shipper/config.py:68-69`, `sensor/shipper/src/sentinel_shipper/sender.py:112-119`.

The API setting accepts arbitrary `http://` hosts and the sender attaches the token. A configuration mistake pointing at a remote plaintext URL exposes the credential to network observers. The default URL is HTTPS; this review did not find evidence that production uses plaintext.

Fix: require HTTPS outside an explicit loopback-only development exception. Test rejection of non-loopback HTTP endpoints before sending any request.

## Verification and limits

- API: 100 existing tests plus two temporary audit reproductions passed (102 total). The reproduction tests asserted the vulnerable behavior and were removed after verification, rather than locking that behavior into the permanent suite. Their inputs and observations are recorded above.
- Python shipper: 174 tests passed.
- Dashboard npm audit: zero known vulnerabilities reported.
- API production-only npm audit: zero known vulnerabilities reported. Full API audit results are described in S4.
- `pip-audit` against the local Python 3.12 shipper environment: no known vulnerabilities reported; the local `sentinel-shipper` package itself is not on PyPI and was reviewed as source. This does not certify a deployed image's resolved packages.
- Gitleaks scanned all 16 reachable commits, about 626 KB: no leaks found. Pattern scanning cannot establish that every possible credential is absent.
- Reviewed authentication order, body/decompression caps, bound SQL, privacy guards, retry/queue logic, packet-parser bounds, container permissions, CI, and dashboard rendering. No SQL injection, direct HTML injection or authentication bypass was established in reviewed paths.
- Public device activity and sensor liveness remain an intentional privacy tradeoff: salted identifiers do not hide household activity patterns. Free-text privacy regexes do not establish complete anonymization.
- No full container CVE scan, packet fuzzing, host compromise assessment, production rate-limit test or external infrastructure audit was performed.

Verdict: address the logging privacy failure, read-path resource abuse and unbounded alert retention, and refresh development dependencies before treating the project as security-hardened.
