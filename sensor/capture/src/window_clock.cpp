#include "window_clock.hpp"

#include "log.hpp"

namespace sentinel {

void WindowClock::start_at(std::int64_t now_sec) {
    if (!current_) current_ = window_of(now_sec);
}

void WindowClock::on_packet(std::int64_t ts_sec, const PacketInfo& pkt,
                            std::uint32_t wire_len) {
    const std::int64_t window = window_of(ts_sec);
    if (!current_) {
        current_ = window;
    } else if (window > *current_) {
        flush();
        current_ = window;
    }
    aggregator_.add(pkt, wire_len);
}

void WindowClock::tick(std::int64_t now_sec) {
    if (current_ && now_sec >= *current_ + kWindowSeconds) {
        flush();
    }
    start_at(now_sec);
}

void WindowClock::flush() {
    if (!current_) return;
    const std::int64_t start = *current_;
    writer_.write(start, aggregator_.to_ndjson(start, kWindowSeconds, iface_));
    ++windows_written_;
    if (log::enabled(log::Level::Debug)) {
        for (const auto& [mac, host] : aggregator_.hosts()) {
            log::debug("  host " + mac.to_string() + " " + host.ip.to_string() +
                       " out=" + std::to_string(host.pkts_out) +
                       " in=" + std::to_string(host.pkts_in));
        }
    }
    log::info("window " + std::to_string(start) + " hosts=" +
              std::to_string(aggregator_.host_count()) +
              " packets=" + std::to_string(aggregator_.packet_count()));
    aggregator_.clear();
    current_.reset();
}

}  // namespace sentinel
