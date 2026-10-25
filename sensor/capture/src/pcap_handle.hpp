// RAII wrapper around a libpcap capture handle.
#pragma once

#include <pcap/pcap.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>

namespace sentinel {

class PcapError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// One captured frame. `data` is only valid until the next call to next().
struct CapturedPacket {
    const std::uint8_t* data = nullptr;
    std::uint32_t caplen = 0;
    std::uint32_t wire_len = 0;
    std::int64_t ts_sec = 0;
};

class PcapHandle {
public:
    struct LiveOptions {
        int snaplen = 128;  // headers only: L2 + IPv6 + ext headers + TCP fit easily
        bool promiscuous = true;
        int timeout_ms = 500;  // kernel buffer timeout before packets are delivered
    };

    enum class ReadResult { Packet, Timeout, EndOfFile };

    // Both factories throw PcapError with libpcap's message on failure.
    static PcapHandle open_live(const std::string& iface, const LiveOptions& options);
    static PcapHandle open_offline(const std::string& path);

    void set_filter(const std::string& expression);
    int datalink() const;

    // Reads the next frame into `out`. Live handles are non-blocking, so
    // Timeout means "nothing buffered right now". Throws PcapError on a read
    // error (for example when the interface goes away).
    ReadResult next(CapturedPacket& out);

    // Live only: waits up to `timeout` for the handle to become readable.
    // libpcap's own read timeout is not reliable everywhere (Linux TPACKET_V3
    // can block indefinitely on an idle link), so the live loop polls itself
    // to keep flushing windows and noticing signals.
    void wait_readable(std::chrono::milliseconds timeout) const;

private:
    struct Closer {
        void operator()(pcap_t* p) const { pcap_close(p); }
    };
    explicit PcapHandle(pcap_t* handle) : handle_(handle) {}

    std::unique_ptr<pcap_t, Closer> handle_;
};

}  // namespace sentinel
