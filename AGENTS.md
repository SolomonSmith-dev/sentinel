# Agent guide

Sentinel is a home-network security monitor: a C++ libpcap sensor, Suricata, an isolation-forest anomaly score and a private Cloudflare Workers + D1 dashboard. `README.md` maps the components, the checks and the privacy design; read it first.

## Layout

- `sensor/capture/`: C++17 libpcap capture. `sensor/shipper/`: Python shipper. `sensor/suricata/`: Suricata config and log retention.
- `ml/`: isolation-forest trainer and evaluator (`ml/train.py`).
- `api/`: Cloudflare Worker (Hono, TypeScript) and D1 migrations.
- `dashboard/`: Vite + React + TypeScript.
- `docs/`: `api.md` and `sensor-format.md` own the component interfaces; `qa-findings.md` and `security_audit_2026-10-31.md` hold review evidence.
- `deploy-sensor.sh`: sensor deploy script.

## Checks

Run the ones for the component you changed (copied from CI):

```bash
cd api && npm ci && npm run typecheck && npm test
cd dashboard && npm ci && npm run build
cmake -S sensor/capture -B build && cmake --build build -j && ctest --test-dir build --output-on-failure
cd sensor/shipper && pip install -e '.[dev]' && pytest -q tests ../suricata/test_retention.py
shellcheck deploy-sensor.sh
```

## Conventions

- Component interfaces are defined in `docs/api.md` and `docs/sensor-format.md`. Change the doc and every component that codes to it together.
- The privacy guard is enforced twice: the shipper refuses batches containing an IP or MAC, and the Worker rejects them (`400 pii_rejected`). Do not weaken either side.

## Safety

- Never commit secrets, tokens or `.env` values.
- Live network telemetry stays private. Public examples, tests and screenshots use synthetic data.
- Deployment commands in the docs are examples, not approval to deploy. Do not deploy or run `deploy-sensor.sh` unless asked.
- `STATUS.md` records dated evidence. Re-verify it against the current system before claiming it still holds.

## Done means

The checks for every component you touched pass, and CI is green on the pull request.
