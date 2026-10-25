# Sensor window format (C++ capture → Python shipper)

Local to earendil only. Raw IPs and MACs live here and never leave the box.

The capture binary writes one file per 10 s window to `$SENTINEL_WINDOWS_DIR` (default `/var/lib/sentinel/windows/`). Each file is written as `<window_start>.ndjson.tmp` and renamed to `<window_start>.ndjson` when complete, so the shipper only ever reads finished files. One JSON object per line, one line per local host seen in that window.

A local host is an address in RFC1918 (`10/8`, `172.16/12`, `192.168/16`), `100.64/10`, IPv6 ULA `fc00::/7` or link-local `fe80::/10`. Each packet is attributed to the local host on the sending side (outbound) or the receiving side (inbound). Packets between two local hosts count for both. Packets with no local side are ignored. Hosts are keyed by MAC; `ip` is the most recent local IP seen for that MAC.

```json
{
  "window_start": 1761370750,
  "window_s": 10,
  "iface": "eth0",
  "host": {"mac": "a4:83:e7:12:34:56", "ip": "192.168.1.20"},
  "pkts_out": 210, "pkts_in": 202,
  "bytes_out": 20311, "bytes_in": 120394,
  "syn_out": 6, "synack_in": 6,
  "distinct_dests": 9,
  "distinct_ports_out": 4,
  "dests": [
    {"ip": "142.250.72.14", "pkts": 80, "bytes": 60000, "syn": 1, "ports": [443]}
  ],
  "inbound_sources": [
    {"ip": "203.0.113.9", "pkts": 600, "syn": 600, "distinct_ports": 1}
  ]
}
```

Rules
- `dests` lists every remote the host sent to in the window, sorted by `pkts` desc, capped at 256 entries. `ports` is the sorted distinct destination ports to that remote, capped at 64. `distinct_dests` and `distinct_ports_out` are exact counts, not limited by the caps.
- `inbound_sources` lists remotes that sent to this host, sorted by `pkts` desc, capped at 64. `syn` counts packets with SYN set and ACK clear.
- `syn_out` counts outbound packets with SYN set and ACK clear. `synack_in` counts inbound SYN+ACK.
- Non-TCP/UDP packets count toward pkts and bytes; ports are only recorded for TCP and UDP.
- Bytes are the captured packet's wire length (`pkthdr.len`).

Replay mode: `sentinel-capture --pcap <file> --out <dir>` reads a pcap file, uses packet timestamps for windowing, flushes the final partial window, and exits 0.
