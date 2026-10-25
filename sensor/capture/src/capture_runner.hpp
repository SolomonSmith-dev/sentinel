// The two top-level capture loops: live interface and pcap replay.
#pragma once

#include <atomic>

#include "config.hpp"

namespace sentinel {

// Set from the SIGINT/SIGTERM handler; the loops poll it between reads.
using StopFlag = std::atomic<bool>;

// Reads `cfg.pcap_file` to the end, windowing by packet timestamp, and
// flushes the final window. Returns the process exit code.
int run_replay(const Config& cfg, const StopFlag& stop);

// Captures from `cfg.iface` until `stop` is set, windowing by wall clock.
// Open and read failures are logged and retried every 5 s. Returns 0 after
// flushing the current window on stop.
int run_live(const Config& cfg, const StopFlag& stop);

}  // namespace sentinel
