# sentinel-capture

A C++17 libpcap sensor. It watches a LAN interface, attributes every IP packet to the local host(s) on either side, and publishes one ndjson file per 10 s window for the Python shipper. The output contract is [`docs/sensor-format.md`](../../docs/sensor-format.md).

## Build and test

Needs CMake 3.20+, a C++17 compiler and libpcap (`apt install libpcap-dev` on Debian/Ubuntu; the macOS SDK copy works as is). nlohmann/json and doctest are fetched at pinned, hash-checked versions.

```sh
cmake -S sensor/capture -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Options: `-DSENTINEL_WERROR=ON` (on by default when `CI` is set), `-DSENTINEL_SANITIZE=ON` (ASan + UBSan), `-DSENTINEL_BUILD_TESTS=OFF`.

Tests: `unit` covers the packet parser (VLAN/QinQ, IPv6 extension headers, fragments, every truncation length of several frames), local-address classification, aggregation and caps, and argument parsing. `replay_*` runs the real binary on the three fixtures in `sensor/tests/fixtures/` and checks exact counts. Regenerate fixtures with `python3 sensor/tests/make_fixtures.py` (deterministic, stdlib only).

## Run

```sh
# live: needs CAP_NET_RAW (or root)
sentinel-capture --iface eth0 --out /var/lib/sentinel/windows

# replay: windows follow packet timestamps; the final partial window is flushed
sentinel-capture --pcap capture.pcap --out /tmp/windows
```

`SENTINEL_IFACE` and `SENTINEL_WINDOWS_DIR` (default `/var/lib/sentinel/windows`) stand in for the flags. In replay, the `iface` field is `pcap` unless `--iface` is given. `--verbose` enables debug logs, the only level that prints addresses.

Live behaviour: windows close on wall-clock 10 s boundaries, one file per window even when it is empty, so the shipper can tell "quiet" from "down". If the interface cannot be opened or goes away, the error is logged and the open retried every 5 s; no windows are written while capture is down. SIGINT/SIGTERM flush the current partial window and exit 0.

Docker: `docker build -t sentinel-capture sensor/capture`. The image runs as uid 10001 with `cap_net_raw` set as a file capability on the binary; compose must grant `cap_add: [NET_RAW]` and `network_mode: host`, and the mounted windows directory must be writable by uid 10001.

## Design notes

- **Header-only capture (snaplen 128).** Ethernet + two VLAN tags + IPv6 + a TCP header fit in 128 bytes. Payloads are never copied out of the kernel, which keeps CPU and memory low and means the sensor never holds content it does not need. Byte counts still use the wire length (`pkthdr.len`).
- **Windowed aggregation.** Detection works on behaviour per host per interval (fan-out, SYN ratios, port spread), not on single packets. Summarising in 10 s windows turns a packet stream into a small, fixed-rate record stream the shipper and model can handle, and files are published atomically (`.tmp`, `fsync`, `rename`) so readers never see partial windows.
- **Memory bound.** State lives for one window and is then dropped. Per host: a fixed 8 KiB bitset for exact distinct ports, plus one entry per distinct peer and per distinct port per peer seen in that window. Output lists are capped (256 dests, 64 ports each, 64 inbound sources) while the distinct counts stay exact, so worst case memory scales with the distinct (host, peer, port) tuples seen in 10 s, not with traffic volume or uptime.
- **Defensive parsing.** All reads go through a bounds-checked cursor. A cut-off L2/L3 header drops the frame; a cut-off L4 header keeps the packet for counts but records no ports or flags. IPv6 extension-header walks are capped at 8 headers.
- **Attribution.** Hosts are keyed by MAC. Frames to broadcast or multicast MACs are not attributed to a receiving host (a group MAC is not a host); the sender still is.
- **Live loop.** The handle is non-blocking and the loop polls its descriptor with a 250 ms timeout, because libpcap's read timeout does not fire on an idle link on every platform (Linux TPACKET_V3). That keeps window flushes on time and makes signals take effect promptly.
