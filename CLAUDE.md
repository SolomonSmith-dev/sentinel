# CLAUDE.md: sentinel

Home-LAN security monitor: C++ libpcap sensor, Suricata, isolation-forest anomaly score, private Cloudflare Workers+D1 dashboard.

## Folder map

- `sensor/`
- `ml/`
- `api/`
- `dashboard/`
- `docs/`

## Routing

| You want to... | Go to |
|----------------|-------|
| Packet sensor | `sensor/` |
| ML anomaly | `ml/` |
| API / D1 | `api/` |
| Dashboard | `dashboard/` |
| Deploy sensor | `deploy-sensor.sh` |
| Agent rules | `AGENTS.md` |

## ICM / Graphify

When `graphify-out/graph.json` exists, answer codebase questions with `graphify query "<q>"` (also `path` / `explain`) before grep or explore agents. Rebuild with `graphify update` after large structural changes. Dual Develop: Hermes-first product build; Cursor for git/PR/evals/parallel. No secrets in commits or docs. Ops spine: `~/Projects/personal-tech-ops`.

## Hard rules

- No secrets, tokens, or `.env` values in commits, docs, or chat logs.
- Prefer project `AGENTS.md` when present; do not fork policy into duplicate files.
- Done means verified commands, not summaries of imagined output.
