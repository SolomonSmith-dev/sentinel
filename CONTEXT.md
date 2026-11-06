# sentinel

Home-LAN security monitor: C++ libpcap sensor, Suricata, isolation-forest anomaly score, private Cloudflare Workers+D1 dashboard.

## Task Routing

| Task Type | Go To | Description |
|-----------|-------|-------------|
| Sensor (C++/pcap) | `sensor/` | Capture + Suricata handoff |
| Anomaly model | `ml/` | Isolation forest / windows |
| Workers API | `api/` | Private email-auth API |
| Dashboard UI | `dashboard/` | Private status UI |
| Status / docs | STATUS.md · docs/ | Ops posture |

## Shared Resources

| Resource | Location | Contains |
|----------|----------|----------|
| AGENTS | `AGENTS.md` | Security + privacy rules |
| Graph | `graphify-out/` | God node: make_window |
| Ops | `~/Projects/personal-tech-ops` | LAN / Tailscale facts |
