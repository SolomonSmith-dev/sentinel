// Header-only decoding of captured Ethernet frames.
//
// The parser never reads past `caplen`. Frames whose network header is cut off
// are rejected; frames whose transport header is cut off are still returned
// (they count toward packets and bytes) but carry no ports; TCP flags are kept
// if their byte was captured.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "addresses.hpp"

namespace sentinel {

enum class Transport : std::uint8_t { Other, Tcp, Udp };

namespace tcp_flag {
constexpr std::uint8_t kFin = 0x01;
constexpr std::uint8_t kSyn = 0x02;
constexpr std::uint8_t kRst = 0x04;
constexpr std::uint8_t kAck = 0x10;
}  // namespace tcp_flag

struct PacketInfo {
    MacAddress src_mac;
    MacAddress dst_mac;
    IpAddress src_ip;
    IpAddress dst_ip;
    Transport transport = Transport::Other;
    bool has_ports = false;  // false for non-TCP/UDP, later fragments, or truncated L4
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint8_t tcp_flags = 0;

    bool is_syn() const {
        return transport == Transport::Tcp && (tcp_flags & tcp_flag::kSyn) &&
               !(tcp_flags & tcp_flag::kAck);
    }
    bool is_synack() const {
        return transport == Transport::Tcp && (tcp_flags & tcp_flag::kSyn) &&
               (tcp_flags & tcp_flag::kAck);
    }
};

// Decodes an Ethernet II frame (optionally 802.1Q / 802.1ad tagged) carrying
// IPv4 or IPv6. Returns nullopt for anything else or for truncated L2/L3.
std::optional<PacketInfo> parse_ethernet(const std::uint8_t* data, std::size_t caplen);

}  // namespace sentinel
