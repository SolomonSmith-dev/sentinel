#include "window_aggregator.hpp"

#include <algorithm>
#include <vector>

#include <nlohmann/json.hpp>

#include "log.hpp"

namespace sentinel {
namespace {

using Json = nlohmann::ordered_json;  // keeps keys in contract order

// Broadcast and multicast frames are not addressed to a single host, so they
// must not create a host entry keyed by a group MAC.
bool is_group_mac(const MacAddress& mac) { return (mac.bytes[0] & 0x01) != 0; }

Json ports_json(const std::set<std::uint16_t>& ports, std::size_t cap) {
    Json out = Json::array();
    for (const std::uint16_t port : ports) {  // std::set iterates in sorted order
        if (out.size() >= cap) break;
        out.push_back(port);
    }
    return out;
}

// Returns map entries ordered by packets desc, then address asc for stable output.
template <typename Stats>
std::vector<std::pair<IpAddress, const Stats*>> top_by_pkts(
    const std::unordered_map<IpAddress, Stats>& map, std::size_t cap) {
    std::vector<std::pair<IpAddress, const Stats*>> rows;
    rows.reserve(map.size());
    for (const auto& [ip, stats] : map) rows.emplace_back(ip, &stats);
    const auto order = [](const auto& a, const auto& b) {
        if (a.second->pkts != b.second->pkts) return a.second->pkts > b.second->pkts;
        return a.first < b.first;
    };
    if (rows.size() > cap) {
        std::partial_sort(rows.begin(), rows.begin() + static_cast<std::ptrdiff_t>(cap),
                          rows.end(), order);
        rows.resize(cap);
    } else {
        std::sort(rows.begin(), rows.end(), order);
    }
    return rows;
}

}  // namespace

void WindowAggregator::add(const PacketInfo& pkt, std::uint32_t wire_len) {
    // A group source MAC is invalid on Ethernet, but exempting it would let a
    // spoofer escape attribution, so the source side is attributed regardless.
    const bool src_local = pkt.src_ip.is_local();
    if (src_local && is_group_mac(pkt.src_mac)) {
        log::debug("group source MAC " + pkt.src_mac.to_string() + " attributed to its source IP");
    }
    const bool dst_local = pkt.dst_ip.is_local() && !is_group_mac(pkt.dst_mac);
    if (!src_local && !dst_local) return;

    ++packets_;
    // A packet between two local hosts counts for both of them.
    if (src_local) add_outbound(pkt, wire_len);
    if (dst_local) add_inbound(pkt, wire_len);
}

HostStats* WindowAggregator::host_for(const MacAddress& mac) {
    if (const auto it = hosts_.find(mac); it != hosts_.end()) return &it->second;
    if (hosts_.size() >= state_.max_hosts) {
        ++overflow_hosts_;
        return nullptr;
    }
    return &hosts_[mac];
}

void WindowAggregator::add_outbound(const PacketInfo& pkt, std::uint32_t wire_len) {
    HostStats* host_ptr = host_for(pkt.src_mac);
    if (!host_ptr) return;
    HostStats& host = *host_ptr;
    host.ip = pkt.src_ip;
    ++host.pkts_out;
    host.bytes_out += wire_len;
    if (pkt.is_syn()) ++host.syn_out;
    if (pkt.has_ports) host.ports_out.set(pkt.dst_port);

    auto it = host.dests.find(pkt.dst_ip);
    if (it == host.dests.end()) {
        if (host.dests.size() >= state_.max_dests_per_host ||
            peer_entries_ >= state_.max_peer_entries) {
            ++overflow_peers_;
            return;
        }
        ++peer_entries_;
        it = host.dests.emplace(pkt.dst_ip, DestStats{}).first;
    }
    DestStats& dest = it->second;
    ++dest.pkts;
    dest.bytes += wire_len;
    if (pkt.is_syn()) ++dest.syn;
    if (pkt.has_ports && (dest.ports.size() < state_.max_ports_per_peer ||
                          dest.ports.count(pkt.dst_port))) {
        dest.ports.insert(pkt.dst_port);
    }
}

void WindowAggregator::add_inbound(const PacketInfo& pkt, std::uint32_t wire_len) {
    HostStats* host_ptr = host_for(pkt.dst_mac);
    if (!host_ptr) return;
    HostStats& host = *host_ptr;
    host.ip = pkt.dst_ip;
    ++host.pkts_in;
    host.bytes_in += wire_len;
    if (pkt.is_synack()) ++host.synack_in;

    auto it = host.inbound.find(pkt.src_ip);
    if (it == host.inbound.end()) {
        if (host.inbound.size() >= state_.max_inbound_per_host ||
            peer_entries_ >= state_.max_peer_entries) {
            ++overflow_peers_;
            return;
        }
        ++peer_entries_;
        it = host.inbound.emplace(pkt.src_ip, InboundStats{}).first;
    }
    InboundStats& source = it->second;
    ++source.pkts;
    if (pkt.is_syn()) ++source.syn;
    if (pkt.has_ports && (source.ports.size() < state_.max_ports_per_peer ||
                          source.ports.count(pkt.dst_port))) {
        source.ports.insert(pkt.dst_port);
    }
}

std::string WindowAggregator::to_ndjson(std::int64_t window_start, int window_s,
                                        const std::string& iface) const {
    std::vector<const std::pair<const MacAddress, HostStats>*> ordered;
    ordered.reserve(hosts_.size());
    for (const auto& entry : hosts_) ordered.push_back(&entry);
    std::sort(ordered.begin(), ordered.end(),
              [](const auto* a, const auto* b) { return a->first.bytes < b->first.bytes; });

    std::string out;
    for (const auto* entry : ordered) {
        const MacAddress& mac = entry->first;
        const HostStats& host = entry->second;

        Json dests = Json::array();
        for (const auto& [ip, d] : top_by_pkts(host.dests, limits_.max_dests)) {
            dests.push_back({{"ip", ip.to_string()},
                             {"pkts", d->pkts},
                             {"bytes", d->bytes},
                             {"syn", d->syn},
                             {"ports", ports_json(d->ports, limits_.max_ports_per_dest)}});
        }

        Json sources = Json::array();
        for (const auto& [ip, s] : top_by_pkts(host.inbound, limits_.max_inbound_sources)) {
            sources.push_back({{"ip", ip.to_string()},
                               {"pkts", s->pkts},
                               {"syn", s->syn},
                               {"distinct_ports", s->ports.size()}});
        }

        Json line;
        line["window_start"] = window_start;
        line["window_s"] = window_s;
        line["iface"] = iface;
        line["host"] = {{"mac", mac.to_string()}, {"ip", host.ip.to_string()}};
        line["pkts_out"] = host.pkts_out;
        line["pkts_in"] = host.pkts_in;
        line["bytes_out"] = host.bytes_out;
        line["bytes_in"] = host.bytes_in;
        line["syn_out"] = host.syn_out;
        line["synack_in"] = host.synack_in;
        line["distinct_dests"] = host.dests.size();
        line["distinct_ports_out"] = host.ports_out.count();
        line["dests"] = std::move(dests);
        line["inbound_sources"] = std::move(sources);

        out += line.dump();
        out += '\n';
    }
    return out;
}

void WindowAggregator::clear() {
    hosts_.clear();
    packets_ = 0;
    peer_entries_ = 0;
    overflow_hosts_ = 0;
    overflow_peers_ = 0;
}

}  // namespace sentinel
