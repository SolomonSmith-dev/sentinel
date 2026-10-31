# Suricata on the sensor CPU

The Core 2 Duo cannot start the upstream Suricata container's x86-64-v2
runtime. Debian's binary package also pulls an SSE4.2-dependent DPDK library.
The Dockerfile builds Suricata 8.0.7 from its SHA-256-checked source archive,
using generic x86-64 C/Rust instructions and no DPDK or Hyperscan libraries.
Rust compilation uses a persistent BuildKit cache for subsequent rebuilds.

`entrypoint.sh` prepares the writable rule/log volumes, then drops to UID/GID
10001. AC matching avoids CPU-specific acceleration. The Compose service keeps
one capture thread, a one-core CPU quota, and a 1 GB memory limit. ET Open rules
are refreshed at startup; the rules volume retains the last downloaded set.

`sentinel.yaml` enables alert-only EVE output. Raw event addresses stay local;
the shipper resolves device hashes and forwards only redacted alert metadata.
