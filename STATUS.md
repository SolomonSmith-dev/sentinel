# STATUS

Updated 2026-10-31 PT. Security fixes deployed; dashboard is private.

## Security deployment

All five findings in `docs/security_audit_2026-10-31.md` are addressed. The owner
also identified live public telemetry as unacceptable; it now requires Cloudflare
Access one-time PIN login for solomonsmithdev@gmail.com, with JWT verification
inside the Worker and private/no-store browser responses. The original public
status checks below are historical and superseded by this section.

- Dashboard Access app: `b3ecd679-4537-4a12-b6ba-003eab91a423`.
- Exact `/api/ingest` Access exception: `7e22ee4c-946a-450d-a16f-686ef481872d`;
  the Worker still enforces its existing bearer token. No telemetry read exception.
- Worker deployment: `850e94c6-46b6-4b54-bb48-b82ef3d83ef4`.
- Verification: owner email login and all five telemetry endpoints passed;
  forged assertions blocked on all five endpoints. Rejected private identifier
  remained null in production D1. Sensor uploads resumed with queue/quarantine 0.
- Two batches affected by the transient Access redirect were restored and sent;
  the sender now retries redirects/403/unexpected 200 responses without losing them.
- Tests: 112 API, 197 Python including retention, four C++ suites; dashboard
  production build and shellcheck passed. API npm audit reports zero vulnerabilities.
- Retention was force-rotated in production: new inode opened, reader advanced,
  no automatic restarts. Existing unrelated ARDA services stayed healthy.

Recovery: set `TELEMETRY_READS_ENABLED=false` and deploy to disable reads. Missing
Access issuer/audience/owner configuration also fails closed. Keep the root
hostname owner-only and preserve only the exact ingestion path exception.
Do not restore public reads as a workaround for authentication errors.


## Result

All five phases done. Live at https://sentinel.solomonsmith.dev, showing labeled seed data until the sensor reports.

| Phase | Result | Proof |
|---|---|---|
| 0 Skeleton, contract, CI | done | repo public, CI green on every push |
| 1 Worker + D1 | done, deployed | vitest 112/112; ingest without token → 401; telemetry requires owner Access login |
| 2 Dashboard | done, deployed | rendered on the live domain in a browser; no console errors except the analytics beacon |
| 3 C++ capture | done | ctest 4/4 (unit + 3 pcap replays with exact values); Linux Docker build verified |
| 4 Shipper + ML | done | pytest 158/158; end to end replay (pcap → capture → shipper → local Worker → D1) produced 2 port_scan, 1 flood, 6 new_device, 0 attack alerts on benign |
| 5 README, deploy script, QA | done | shellcheck clean; QA findings in `docs/qa-findings.md`, 7 of 9 fixed |

Changes from the spec: the dashboard is served by the Worker itself (one deploy, same origin) instead of a separate Pages project; D1 gets 60 s rollups instead of 10 s windows; polling instead of SSE; the deploy script is `deploy-sensor.sh` (earendil is an ARDA agent, not a host). The sensor host is home-server.

## Production deployment

- Cloud: migration 0003 applied; Worker/dashboard version `ce6e9794-8874-4d27-9d71-92ed506d5412` deployed.
- Sensor: `~/sentinel` on home-server, capture interface `enp4s0f0`. Capture, shipper, and Suricata are running with zero automatic restarts at verification.
- Credentials: replacement token and stable salt provisioned with explicit approval under `~/.config/sentinel/`; directory mode 0700, files owned by shipper UID 10001 with mode 0400, mounted read-only. No `.env` created or changed; values are absent from the Docker environment and repository.
- Verification: repeated real uploads return 200; `sensor-01` reports with queue depth 0 and `seed_active=false`. Queue and quarantine are empty. Public response privacy scans and authenticated hostname/UTF-8 rejection tests pass.
- IDS: 52,939 ET Open rules loaded, zero rule failures. A harmless diagnostic marker triggered SID 2100498 and reached the production API and dashboard, including after final tuning. These "id check returned root" alerts are deliberate verification events, not evidence of a compromise.
- Resource check: IDS uses about 1.3 GiB within a 1.5 GiB bound, no swap use, memory-limit pressure, or OOM events. Existing ARDA API remains healthy.
- Local checks: 100 API tests, 174 shipper tests, 4 C++ ctest suites, API typecheck, dashboard build, shellcheck, Compose validation, and whitespace checks pass.

Validate or redeploy using mounted credentials:

```sh
/usr/bin/ssh home-server 'cd ~/sentinel && ./deploy-sensor.sh --credentials --dry-run'
/usr/bin/ssh home-server 'cd ~/sentinel && ./deploy-sensor.sh --credentials'
curl -fsS https://sentinel.solomonsmith.dev/api/metrics | python3 -m json.tool
```

The dashboard labels retained synthetic history alongside live reporting. ML imports and a tiny fit passed on the actual CPU; live scores remain null until the normal bootstrap has at least two hours of features and enough rows.

## Operational limits

- **CPU (Core 2 Duo, no SSE4.2).** The shipper probes numpy/sklearn in a subprocess at start. If it crashes (SIGILL), the log says so and the shipper runs rules-only with `score: null`. Rules and shipping still work. The import-and-fit probe passed on the real hardware; initial scores are null until bootstrap training.
- **Suricata load.** Capped at 1 core and 1.5 GiB, 1 af-packet thread, with low grouping and bounded flow/stream state. If ARDA or Jellyfin slow down, stop the suricata service first.
- **What the NIC sees.** Capture observes traffic visible to enp4s0f0. Whole-LAN visibility requires appropriate switch mirroring or gateway placement; that coverage was not established by the pipeline test.
- **D1 budget.** 100k row-writes a day on the free tier, and index entries count. Estimated 60k a day for 20 active devices. Check with `cd ~/Projects/sentinel/api && npx wrangler d1 info sentinel`.

## New dependencies

- npm (api): hono 4.13.13, zod 4.6.7; dev: wrangler 4.152.0, vitest 5.0.5, @cloudflare/vitest-plugin 1.4.7, typescript 5.9.3, @cloudflare/workers-types
- npm (dashboard): react 19.3.0, react-dom 19.3.0, recharts 3.10.1; dev: vite 8.3.4, tailwindcss 4.3.3, @tailwindcss/vite, @vitejs/plugin-react, typescript 5.9.3
- pip (shipper): httpx 0.28.1, numpy 2.3.5, scipy 1.18.1, scikit-learn 1.9.1, joblib 1.6.0; dev: pytest 9.1.1, respx 0.23.1
- CMake FetchContent: nlohmann/json, a test framework (pinned tags in `sensor/capture/CMakeLists.txt`)
- Docker images: jasonish/suricata:8.0.7, debian bookworm-slim, python:3.12-slim, busybox:1.37.0
- Build-time downloads: iptoasn ip2country-v4 (PDDL), IEEE oui.csv
- On the Mac: Homebrew cmake 4.4

## Open issues

- Local QA fixes: F2 cache canonicalization and cron row-count snapshot, F5 UTF-8 detail cap, F6 local-DNS hostname guard, F9 capability hardening. Cloud deployment verified 2026-10-31: migration 0003 applied; Worker version 373c6d97-cd2c-4d61-97d1-518bfea7f826 live. Public endpoints, assets, security headers, conditional requests, browser rendering, and scheduled snapshot refresh verified. Production token rotated with explicit approval; owner-only token/salt files live under ~/.config/sentinel on home-server and are mounted read-only, outside the checkout. Capture and shipper are deployed, reporting sensor-01 with an empty queue; authenticated hostname/UTF-8 production probes pass. Suricata 8.0.7 is deployed from SHA-256-checked source with generic x86-64 instructions; the final diagnostic alert reached production. IDS memory is bounded at 1.5 GiB. Dashboard version ce6e9794-8874-4d27-9d71-92ed506d5412 labels live reporting and retained synthetic history correctly. See docs/qa-findings.md for limits.
- Capture caps are first-come: spoofing more than 4096 MACs in one 10 s window crowds out real hosts (logged, not alerted).
- IDS EVE retention is now bounded: 16 MiB/hourly rotation, 128 MiB/24-hour archives, 64 MiB per-file emergency limit. Reader drains unread archived inodes; retention loss is warned.
- Seed device IDs all start with `dev-5e0`. The fix is on branch `seed-hash-refresh`. Re-seeding costs about 58k D1 writes, so deploy it after a UTC day reset (17:00 PT): merge, `npx wrangler deploy`, delete `is_seed=1` rows, `npm run seed:remote`.
- `.env.example` still says "earendil" in two comments (edit blocked by the `.env` deny rule).
- Portfolio PR to merge: https://github.com/SolomonSmith-dev/SolomonSmith-dev.github.io/pull/6 (Sentinel card below CourtRules). Check the card against the master resume rule in that repo's CLAUDE.md.
- README and dashboard now describe live telemetry with retained synthetic history. The separate portfolio card was not changed.
