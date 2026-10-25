#include "pcap_handle.hpp"

#include <poll.h>

#include <thread>

namespace sentinel {
namespace {

// Converts a negative pcap_set_* / pcap_activate status into an exception.
void check_status(pcap_t* p, int status, const std::string& what) {
    if (status < 0) {
        std::string msg = what + ": " + pcap_statustostr(status);
        if (status == PCAP_ERROR) msg += std::string(" (") + pcap_geterr(p) + ")";
        throw PcapError(msg);
    }
}

}  // namespace

PcapHandle PcapHandle::open_live(const std::string& iface, const LiveOptions& options) {
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t* raw = pcap_create(iface.c_str(), errbuf);
    if (raw == nullptr) throw PcapError("pcap_create " + iface + ": " + errbuf);
    PcapHandle handle(raw);  // owns `raw` from here on, even if a step below throws

    check_status(raw, pcap_set_snaplen(raw, options.snaplen), "pcap_set_snaplen");
    check_status(raw, pcap_set_promisc(raw, options.promiscuous ? 1 : 0), "pcap_set_promisc");
    check_status(raw, pcap_set_timeout(raw, options.timeout_ms), "pcap_set_timeout");
    check_status(raw, pcap_activate(raw), "pcap_activate " + iface);
    if (pcap_setnonblock(raw, 1, errbuf) != 0) {
        throw PcapError(std::string("pcap_setnonblock: ") + errbuf);
    }
    return handle;
}

PcapHandle PcapHandle::open_offline(const std::string& path) {
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t* raw = pcap_open_offline(path.c_str(), errbuf);
    if (raw == nullptr) throw PcapError("pcap_open_offline " + path + ": " + errbuf);
    return PcapHandle(raw);
}

void PcapHandle::set_filter(const std::string& expression) {
    bpf_program program{};
    if (pcap_compile(handle_.get(), &program, expression.c_str(), 1,
                     PCAP_NETMASK_UNKNOWN) != 0) {
        throw PcapError("pcap_compile '" + expression + "': " + pcap_geterr(handle_.get()));
    }
    const int rc = pcap_setfilter(handle_.get(), &program);
    pcap_freecode(&program);
    if (rc != 0) throw PcapError(std::string("pcap_setfilter: ") + pcap_geterr(handle_.get()));
}

void PcapHandle::wait_readable(std::chrono::milliseconds timeout) const {
    const int fd = pcap_get_selectable_fd(handle_.get());
    if (fd < 0) {  // no pollable descriptor on this platform: fall back to a short sleep
        std::this_thread::sleep_for(timeout);
        return;
    }
    pollfd pfd{fd, POLLIN, 0};
    // EINTR (a signal) simply returns early; the caller re-checks its stop flag.
    ::poll(&pfd, 1, static_cast<int>(timeout.count()));
}

int PcapHandle::datalink() const { return pcap_datalink(handle_.get()); }

PcapHandle::ReadResult PcapHandle::next(CapturedPacket& out) {
    pcap_pkthdr* header = nullptr;
    const u_char* data = nullptr;
    const int rc = pcap_next_ex(handle_.get(), &header, &data);
    if (rc == 1) {
        out.data = data;
        out.caplen = header->caplen;
        out.wire_len = header->len;
        out.ts_sec = static_cast<std::int64_t>(header->ts.tv_sec);
        return ReadResult::Packet;
    }
    if (rc == 0) return ReadResult::Timeout;
    if (rc == PCAP_ERROR_BREAK) return ReadResult::EndOfFile;
    throw PcapError(std::string("pcap_next_ex: ") + pcap_geterr(handle_.get()));
}

}  // namespace sentinel
