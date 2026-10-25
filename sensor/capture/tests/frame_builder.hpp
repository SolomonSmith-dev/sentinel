// Test helper: assembles raw Ethernet frames byte by byte. Checksums are left
// zero because the parser never validates them.
#pragma once

#include <cstdint>
#include <initializer_list>
#include <vector>

#include "addresses.hpp"
#include "packet_parser.hpp"

namespace test {

using Bytes = std::vector<std::uint8_t>;

class FrameBuilder {
public:
    FrameBuilder& ethernet(std::uint16_t ether_type,
                           std::initializer_list<std::uint16_t> vlan_tpids = {}) {
        append({0x02, 0, 0, 0, 0, 0x02});  // dst MAC
        append({0x02, 0, 0, 0, 0, 0x01});  // src MAC
        std::uint16_t vid = 10;
        for (const std::uint16_t tpid : vlan_tpids) {
            u16(tpid);
            u16(vid++);
        }
        u16(ether_type);
        return *this;
    }

    FrameBuilder& ipv4(const char* src, const char* dst, std::uint8_t proto,
                       std::uint16_t frag_field = 0x4000) {
        append({0x45, 0});
        u16(0);  // total length (unused by the parser)
        u16(0);  // id
        u16(frag_field);
        append({64, proto, 0, 0});
        address(src);
        address(dst);
        return *this;
    }

    FrameBuilder& ipv6(const char* src, const char* dst, std::uint8_t next_header) {
        append({0x60, 0, 0, 0});
        u16(0);  // payload length
        append({next_header, 64});
        address(src);
        address(dst);
        return *this;
    }

    // Generic 8-byte IPv6 extension header (hop-by-hop, destination options).
    FrameBuilder& ipv6_ext(std::uint8_t next_header) {
        append({next_header, 0, 0, 0, 0, 0, 0, 0});
        return *this;
    }

    FrameBuilder& ipv6_fragment(std::uint8_t next_header, std::uint16_t offset_units) {
        append({next_header, 0});
        u16(static_cast<std::uint16_t>(offset_units << 3));
        append({0, 0, 0, 1});
        return *this;
    }

    FrameBuilder& tcp(std::uint16_t sport, std::uint16_t dport, std::uint8_t flags) {
        u16(sport);
        u16(dport);
        append({0, 0, 0, 1, 0, 0, 0, 0});  // seq, ack
        append({0x50, flags});
        append({0xFA, 0xF0, 0, 0, 0, 0});  // window, checksum, urgent
        return *this;
    }

    FrameBuilder& udp(std::uint16_t sport, std::uint16_t dport) {
        u16(sport);
        u16(dport);
        append({0, 8, 0, 0});
        return *this;
    }

    FrameBuilder& icmp() {
        append({8, 0, 0, 0, 0, 1, 0, 1});
        return *this;
    }

    const Bytes& bytes() const { return bytes_; }

private:
    void append(std::initializer_list<std::uint8_t> b) { bytes_.insert(bytes_.end(), b); }
    void u16(std::uint16_t v) {
        bytes_.push_back(static_cast<std::uint8_t>(v >> 8));
        bytes_.push_back(static_cast<std::uint8_t>(v & 0xFF));
    }
    void address(const char* text) {
        const auto ip = sentinel::IpAddress::parse(text);
        const std::size_t n = ip.family() == sentinel::IpAddress::Family::V4 ? 4 : 16;
        bytes_.insert(bytes_.end(), ip.bytes().begin(),
                      ip.bytes().begin() + static_cast<std::ptrdiff_t>(n));
    }

    Bytes bytes_;
};

// A parsed packet without going through bytes, for aggregator tests.
inline sentinel::PacketInfo packet(const char* src, const char* dst, std::uint8_t src_mac_tail,
                                   std::uint8_t dst_mac_tail, sentinel::Transport transport,
                                   std::uint16_t sport, std::uint16_t dport,
                                   std::uint8_t flags = 0) {
    sentinel::PacketInfo p;
    p.src_mac.bytes = {0x02, 0, 0, 0, 0, src_mac_tail};
    p.dst_mac.bytes = {0x02, 0, 0, 0, 0, dst_mac_tail};
    p.src_ip = sentinel::IpAddress::parse(src);
    p.dst_ip = sentinel::IpAddress::parse(dst);
    p.transport = transport;
    p.has_ports = transport != sentinel::Transport::Other;
    p.src_port = sport;
    p.dst_port = dport;
    p.tcp_flags = flags;
    return p;
}

}  // namespace test
