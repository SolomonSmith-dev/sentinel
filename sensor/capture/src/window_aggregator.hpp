// Per-local-host flow statistics for one capture window.
#pragma once

#include <bitset>
#include <cstdint>
#include <set>
#include <string>
#include <unordered_map>

#include "addresses.hpp"
#include "packet_parser.hpp"

namespace sentinel {

// Output caps from docs/sensor-format.md. Distinct counts are never capped.
struct OutputLimits {
    std::size_t max_dests = 256;
    std::size_t max_ports_per_dest = 64;
    std::size_t max_inbound_sources = 64;
};

// Memory caps for state held during one window. A LAN attacker spoofing source
// MACs or addresses could otherwise grow it without limit. Once a cap is hit,
// new entries are counted in the overflow counters instead of stored; existing
// entries keep updating. Distinct counts are exact up to these caps and a lower
// bound beyond them.
struct StateLimits {
    std::size_t max_hosts = 4096;               // 8 KiB port bitset each
    std::size_t max_dests_per_host = 1024;
    std::size_t max_inbound_per_host = 1024;
    std::size_t max_ports_per_peer = 256;       // stored ports per dest / inbound source
    std::size_t max_peer_entries = 262144;      // dests + inbound across all hosts
};

struct DestStats {
    std::uint64_t pkts = 0;
    std::uint64_t bytes = 0;
    std::uint64_t syn = 0;
    std::set<std::uint16_t> ports;  // destination ports on the remote
};

struct InboundStats {
    std::uint64_t pkts = 0;
    std::uint64_t syn = 0;
    std::set<std::uint16_t> ports;  // ports on the local host this remote targeted
};

struct HostStats {
    IpAddress ip;  // most recent local IP seen for this MAC
    std::uint64_t pkts_out = 0;
    std::uint64_t pkts_in = 0;
    std::uint64_t bytes_out = 0;
    std::uint64_t bytes_in = 0;
    std::uint64_t syn_out = 0;
    std::uint64_t synack_in = 0;
    std::bitset<65536> ports_out;  // exact distinct destination ports, fixed 8 KiB
    std::unordered_map<IpAddress, DestStats> dests;
    std::unordered_map<IpAddress, InboundStats> inbound;
};

class WindowAggregator {
public:
    explicit WindowAggregator(OutputLimits limits = {}, StateLimits state = {})
        : limits_(limits), state_(state) {}

    // Attributes one packet to the local host(s) on either side. Packets with
    // no local side are ignored. `wire_len` is pcap_pkthdr.len.
    void add(const PacketInfo& pkt, std::uint32_t wire_len);

    // Renders one JSON line per host (sorted by MAC), each ending in '\n'.
    std::string to_ndjson(std::int64_t window_start, int window_s,
                          const std::string& iface) const;

    void clear();

    std::size_t host_count() const { return hosts_.size(); }
    std::uint64_t packet_count() const { return packets_; }
    // Hosts dropped because the host table was full, and peer entries (dests,
    // inbound sources) dropped because a per-host or window-wide cap was hit.
    std::uint64_t overflow_hosts() const { return overflow_hosts_; }
    std::uint64_t overflow_peers() const { return overflow_peers_; }
    const std::unordered_map<MacAddress, HostStats>& hosts() const { return hosts_; }

private:
    void add_outbound(const PacketInfo& pkt, std::uint32_t wire_len);
    void add_inbound(const PacketInfo& pkt, std::uint32_t wire_len);

    // Returns the host for `mac`, or nullptr (and counts it) if the table is full.
    HostStats* host_for(const MacAddress& mac);

    OutputLimits limits_;
    StateLimits state_;
    std::unordered_map<MacAddress, HostStats> hosts_;
    std::uint64_t packets_ = 0;
    std::uint64_t peer_entries_ = 0;
    std::uint64_t overflow_hosts_ = 0;
    std::uint64_t overflow_peers_ = 0;
};

}  // namespace sentinel
