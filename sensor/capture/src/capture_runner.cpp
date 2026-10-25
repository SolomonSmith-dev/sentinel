#include "capture_runner.hpp"

#include <chrono>
#include <exception>
#include <optional>
#include <thread>

#include "log.hpp"
#include "packet_parser.hpp"
#include "pcap_handle.hpp"
#include "window_clock.hpp"

namespace sentinel {
namespace {

constexpr const char* kBpfFilter = "ip or ip6";
constexpr auto kRetryInterval = std::chrono::seconds(5);
constexpr auto kPollInterval = std::chrono::milliseconds(250);

std::int64_t wall_clock_sec() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

// Sleeps up to `duration`, waking early if a stop is requested.
void interruptible_sleep(std::chrono::milliseconds duration, const StopFlag& stop) {
    const auto deadline = std::chrono::steady_clock::now() + duration;
    while (!stop.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void require_ethernet(const PcapHandle& handle) {
    if (handle.datalink() != DLT_EN10MB) {
        throw PcapError("unsupported link type " + std::to_string(handle.datalink()) +
                        " (hosts are keyed by MAC, so Ethernet is required)");
    }
}

// Parses and aggregates one frame. Returns false if it was not IPv4/IPv6.
bool ingest(WindowClock& clock, const CapturedPacket& frame) {
    const auto pkt = parse_ethernet(frame.data, frame.caplen);
    if (!pkt) return false;
    clock.on_packet(frame.ts_sec, *pkt, frame.wire_len);
    return true;
}

}  // namespace

int run_replay(const Config& cfg, const StopFlag& stop) {
    try {
        PcapHandle handle = PcapHandle::open_offline(cfg.pcap_file);
        require_ethernet(handle);
        WindowClock clock(WindowWriter(cfg.out_dir), cfg.iface);

        CapturedPacket frame;
        std::uint64_t skipped = 0;
        while (!stop.load() && handle.next(frame) == PcapHandle::ReadResult::Packet) {
            if (!ingest(clock, frame)) ++skipped;
        }
        clock.flush();
        log::info("replay done: windows=" + std::to_string(clock.windows_written()) +
                  " skipped_frames=" + std::to_string(skipped));
        return 0;
    } catch (const std::exception& e) {
        log::error(e.what());
        return 1;
    }
}

int run_live(const Config& cfg, const StopFlag& stop) {
    std::optional<WindowClock> clock;
    try {
        clock.emplace(WindowWriter(cfg.out_dir), cfg.iface);
    } catch (const std::exception& e) {
        log::error(e.what());  // output dir unusable: nothing to retry against
        return 1;
    }

    while (!stop.load()) {
        try {
            PcapHandle handle = PcapHandle::open_live(cfg.iface, PcapHandle::LiveOptions{});
            require_ethernet(handle);
            handle.set_filter(kBpfFilter);
            log::info("capturing on " + cfg.iface);
            clock->start_at(wall_clock_sec());

            CapturedPacket frame;
            while (!stop.load()) {
                if (handle.next(frame) == PcapHandle::ReadResult::Packet) {
                    ingest(*clock, frame);
                } else {
                    handle.wait_readable(kPollInterval);
                }
                clock->tick(wall_clock_sec());
            }
        } catch (const std::exception& e) {
            log::error(std::string(e.what()) + "; retrying in 5 s");
            // Publish what we have, but write no windows while capture is down:
            // an empty file would falsely claim the network was quiet.
            try {
                clock->flush();
            } catch (const std::exception& flush_error) {
                log::error(flush_error.what());
            }
            interruptible_sleep(kRetryInterval, stop);
        }
    }

    try {
        clock->flush();
    } catch (const std::exception& e) {
        log::error(e.what());
        return 1;
    }
    log::info("stopped");
    return 0;
}

}  // namespace sentinel
