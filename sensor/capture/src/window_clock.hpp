// Drives window boundaries: decides when the current window is complete,
// hands it to the writer, and starts the next one.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include "packet_parser.hpp"
#include "window_aggregator.hpp"
#include "window_writer.hpp"

namespace sentinel {

constexpr int kWindowSeconds = 10;

// Start of the 10 s window containing `ts_sec` (floor, also for negative times).
constexpr std::int64_t window_of(std::int64_t ts_sec) {
    const std::int64_t r = ts_sec % kWindowSeconds;
    return ts_sec - (r < 0 ? r + kWindowSeconds : r);
}

class WindowClock {
public:
    WindowClock(WindowWriter writer, std::string iface)
        : writer_(std::move(writer)), iface_(std::move(iface)) {}

    // Opens the window containing `now_sec` if none is open. Used by live mode,
    // where windows follow the wall clock even when no packets arrive.
    void start_at(std::int64_t now_sec);

    // Adds a packet stamped `ts_sec`. A packet from a later window closes the
    // current one first; a late packet (clock skew, reordering) is folded into
    // the current window rather than reopening a closed file.
    void on_packet(std::int64_t ts_sec, const PacketInfo& pkt, std::uint32_t wire_len);

    // Live mode: closes the current window once the wall clock passes its end,
    // and opens the window containing `now_sec`.
    void tick(std::int64_t now_sec);

    // Writes the open window (even if partial) and leaves no window open.
    void flush();

    std::uint64_t windows_written() const { return windows_written_; }

private:
    WindowWriter writer_;
    std::string iface_;
    WindowAggregator aggregator_;
    std::optional<std::int64_t> current_;
    std::uint64_t windows_written_ = 0;
};

}  // namespace sentinel
