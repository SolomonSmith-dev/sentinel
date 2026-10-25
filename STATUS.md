# STATUS

Updated 2026-10-25 00:05 PT. Build started 2026-10-24 22:50 PT.

## Result

All five phases done. Live at https://sentinel.solomonsmith.dev, showing labeled seed data until the sensor reports.

| Phase | Result | Proof |
|---|---|---|
| 0 Skeleton, contract, CI | done | repo public, CI green on every push |
| 1 Worker + D1 | done, deployed | vitest 80/80; prod: no token → 401, every read endpoint 200 |
| 2 Dashboard | done, deployed | rendered on the live domain in a browser; no console errors except the analytics beacon |
| 3 C++ capture | done | ctest 4/4 (unit + 3 pcap replays with exact values); Linux Docker build verified |
| 4 Shipper + ML | done | pytest 158/158; end to end replay (pcap → capture → shipper → local Worker → D1) produced 2 port_scan, 1 flood, 6 new_device, 0 attack alerts on benign |
| 5 README, deploy script, QA | done | shellcheck clean; QA findings in `docs/qa-findings.md`, 7 of 9 fixed |

Changes from the spec: the dashboard is served by the Worker itself (one deploy, same origin) instead of a separate Pages project; D1 gets 60 s rollups instead of 10 s windows; polling instead of SSE; the deploy script is `deploy-sensor.sh` (earendil is an ARDA agent, not a host). The sensor host is home-server.

## Your steps (about 25 minutes, mostly waiting on the build)

1. **iTerm, Mac.** Make the token and put it on the Worker and on home-server. It is never printed or written to the repo.
   ```
   cd ~/Projects/sentinel/api
   TOKEN=$(openssl rand -hex 32)
   printf '%s' "$TOKEN" | npx wrangler secret put SENTINEL_TOKEN
   printf '%s\n' "$TOKEN" | /usr/bin/ssh home-server 'umask 077; mkdir -p ~/.config/sentinel; cat > ~/.config/sentinel/token'
   unset TOKEN
   ```
   Worked when: wrangler prints `Success! Uploaded secret SENTINEL_TOKEN` and the ssh line prints nothing.

2. **iTerm, Mac.** Deploy the sensor stack on home-server (clones to `~/sentinel`; the salt is generated there).
   ```
   /usr/bin/ssh home-server 'git clone https://github.com/SolomonSmith-dev/sentinel.git ~/sentinel && cd ~/sentinel && ./deploy-sensor.sh --dry-run && ./deploy-sensor.sh'
   ```
   Worked when: it ends with a `docker compose ps` table showing suricata, sentinel-capture and sentinel-shipper `Up`. The first build compiles C++ and installs scikit-learn on a Core 2 Duo, so expect 15 to 30 minutes.

3. **iTerm, Mac.** Confirm the sensor is reporting, about 2 minutes after step 2.
   ```
   curl -s https://sentinel.solomonsmith.dev/api/metrics | python3 -m json.tool | /usr/bin/grep -A3 '"sensor"'
   ```
   Worked when: `"sensor_id": "sensor-01"`. Failed if you see `"sensor": null`. Then run `/usr/bin/ssh home-server 'cd ~/sentinel && docker compose -f sensor/docker-compose.yml logs --tail 30 sentinel-shipper'`.

Kill switches: `/usr/bin/ssh home-server 'cd ~/sentinel && docker compose -f sensor/docker-compose.yml down'`, or set the Worker var `INGEST_ENABLED=false`.

## Watch on first deploy

- **CPU (Core 2 Duo, no SSE4.2).** The shipper probes numpy/sklearn in a subprocess at start. If it crashes (SIGILL), the log says so and the shipper runs rules-only with `score: null`. Rules and shipping still work. numpy is pinned to 2.3 for this CPU; not tested on the real hardware.
- **Suricata load.** Capped at 1 core and 1 GB, 1 af-packet thread. If ARDA or Jellyfin slow down, stop the suricata service first.
- **What the NIC sees.** You said home-server sees LAN traffic. If the device grid shows only one or two devices, it is only seeing its own traffic and a mirror port or gateway placement is needed.
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

- QA F5 (low): the 2 KB `detail` cap counts UTF-16 units, not bytes.
- QA F6 (low): no hostname guard on the Worker.
- QA F9 (partial): `no-new-privileges` only verified on Docker Desktop; NET_ADMIN not dropped from capture.
- QA F2 (partial): cache keys include arbitrary query params, so `?x=random` bypasses the 10 s read cache.
- Capture caps are first-come: spoofing more than 4096 MACs in one 10 s window crowds out real hosts (logged, not alerted).
- `eve.json` is never rotated (small, alerts only).
- Seed device IDs all start with `dev-5e0`. The fix is on branch `seed-hash-refresh`. Re-seeding costs about 58k D1 writes, so deploy it after a UTC day reset (17:00 PT): merge, `npx wrangler deploy`, delete `is_seed=1` rows, `npm run seed:remote`.
- `.env.example` still says "earendil" in two comments (edit blocked by the `.env` deny rule).
- Portfolio PR to merge: https://github.com/SolomonSmith-dev/SolomonSmith-dev.github.io/pull/6 (Sentinel card below CourtRules). Check the card against the master resume rule in that repo's CLAUDE.md.
- Once real sensor data flows: drop the demo-data wording in this README and the portfolio card.
