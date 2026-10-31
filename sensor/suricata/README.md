# Suricata on the sensor CPU

The Core 2 Duo cannot start the upstream Suricata container's x86-64-v2
runtime. Debian's binary package also pulls an SSE4.2-dependent DPDK library.
The Dockerfile builds Suricata 8.0.7 from its SHA-256-checked source archive,
using generic x86-64 C/Rust instructions and no DPDK or Hyperscan libraries.
Rust compilation uses a persistent BuildKit cache for subsequent rebuilds.

`entrypoint.sh` prepares the writable rule/log volumes, then drops to UID/GID
10001. AC-KS matching avoids CPU-specific acceleration. The Compose service keeps
one capture thread, a one-core CPU quota, and a 1.5 GiB memory limit. The full
52k-rule set pressed against 1 GiB in live testing; low grouping, shared matcher
contexts, and bounded flow/stream state limit additional growth. ET Open rules
are refreshed at startup; the rules volume retains the last downloaded set.

`sentinel.yaml` enables alert-only EVE output. Raw event addresses stay local;
the shipper resolves device hashes and forwards only redacted alert metadata.


## Alert retention

The supervisor renames `eve.json` and signals Suricata to reopen it at 16 MiB
or one hour, checking every two seconds. Archives retain their inodes. The
shipper follows its saved inode, finishes unread archived records, then moves
to newer files. Checkpoints are still committed only after durable queuing.
Archives expire after 24 hours or when their combined size exceeds 128 MiB,
oldest first. Eviction logs a warning about potential unread data loss; a
missing shipper checkpoint inode also warns. Fewer than 1 GiB free logs an error.

A 64 MiB per-file OS limit protects against bursts outrunning rotation. Hitting
that emergency limit can interrupt IDS logging and restart the service, rather
than consuming the host disk. Normal rotation uses rename/reopen, not
copytruncate. Console logs use Docker's existing bounded logging policy.
The archive budget is enforced every two seconds, so transient usage can exceed
128 MiB by the active/just-rotated file. Data beyond retention is deliberately
lost if the shipper cannot keep up. Send SIGUSR1 to container PID 1 for an
operational rotation check. No raw EVE files are uploaded.
