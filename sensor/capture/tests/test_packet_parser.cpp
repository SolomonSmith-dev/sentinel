#include <doctest/doctest.h>

#include <memory>

#include "frame_builder.hpp"
#include "packet_parser.hpp"

using sentinel::parse_ethernet;
using sentinel::Transport;
using test::FrameBuilder;
namespace flag = sentinel::tcp_flag;

namespace {

constexpr std::uint16_t kIpv4 = 0x0800;
constexpr std::uint16_t kIpv6 = 0x86DD;
constexpr std::uint16_t kArp = 0x0806;
constexpr std::uint16_t kDot1Q = 0x8100;
constexpr std::uint16_t kDot1ad = 0x88A8;

// Copies the first `len` bytes into an exact-size heap buffer so that any read
// past `len` is an out-of-bounds access that ASan reports.
std::optional<sentinel::PacketInfo> parse_prefix(const test::Bytes& frame, std::size_t len) {
    auto buf = std::make_unique<std::uint8_t[]>(len == 0 ? 1 : len);
    std::copy(frame.begin(), frame.begin() + static_cast<std::ptrdiff_t>(len), buf.get());
    return parse_ethernet(buf.get(), len);
}

}  // namespace

TEST_CASE("IPv4 TCP SYN") {
    const auto frame = FrameBuilder()
                           .ethernet(kIpv4)
                           .ipv4("192.168.1.20", "203.0.113.9", 6)
                           .tcp(51000, 443, flag::kSyn)
                           .bytes();
    const auto pkt = parse_ethernet(frame.data(), frame.size());
    REQUIRE(pkt);
    CHECK(pkt->src_mac.to_string() == "02:00:00:00:00:01");
    CHECK(pkt->dst_mac.to_string() == "02:00:00:00:00:02");
    CHECK(pkt->src_ip.to_string() == "192.168.1.20");
    CHECK(pkt->dst_ip.to_string() == "203.0.113.9");
    CHECK(pkt->transport == Transport::Tcp);
    CHECK(pkt->has_ports);
    CHECK(pkt->src_port == 51000);
    CHECK(pkt->dst_port == 443);
    CHECK(pkt->is_syn());
    CHECK_FALSE(pkt->is_synack());
}

TEST_CASE("SYN-ACK is not counted as a SYN") {
    const auto frame = FrameBuilder()
                           .ethernet(kIpv4)
                           .ipv4("203.0.113.9", "192.168.1.20", 6)
                           .tcp(443, 51000, flag::kSyn | flag::kAck)
                           .bytes();
    const auto pkt = parse_ethernet(frame.data(), frame.size());
    REQUIRE(pkt);
    CHECK_FALSE(pkt->is_syn());
    CHECK(pkt->is_synack());
}

TEST_CASE("IPv4 UDP and ICMP") {
    const auto udp = FrameBuilder()
                         .ethernet(kIpv4)
                         .ipv4("192.168.1.20", "198.51.100.53", 17)
                         .udp(53001, 53)
                         .bytes();
    auto pkt = parse_ethernet(udp.data(), udp.size());
    REQUIRE(pkt);
    CHECK(pkt->transport == Transport::Udp);
    CHECK(pkt->dst_port == 53);

    const auto icmp =
        FrameBuilder().ethernet(kIpv4).ipv4("192.168.1.20", "192.168.1.1", 1).icmp().bytes();
    pkt = parse_ethernet(icmp.data(), icmp.size());
    REQUIRE(pkt);
    CHECK(pkt->transport == Transport::Other);
    CHECK_FALSE(pkt->has_ports);
}

TEST_CASE("802.1Q and 802.1ad tagged frames") {
    const auto single = FrameBuilder()
                            .ethernet(kIpv4, {kDot1Q})
                            .ipv4("192.168.1.12", "203.0.113.102", 6)
                            .tcp(50002, 443, flag::kSyn)
                            .bytes();
    auto pkt = parse_ethernet(single.data(), single.size());
    REQUIRE(pkt);
    CHECK(pkt->src_ip.to_string() == "192.168.1.12");
    CHECK(pkt->dst_port == 443);
    CHECK(pkt->is_syn());

    const auto qinq = FrameBuilder()
                          .ethernet(kIpv6, {kDot1ad, kDot1Q})
                          .ipv6("fd00::1", "2001:db8::1", 17)
                          .udp(5353, 53)
                          .bytes();
    pkt = parse_ethernet(qinq.data(), qinq.size());
    REQUIRE(pkt);
    CHECK(pkt->src_ip.to_string() == "fd00::1");
    CHECK(pkt->dst_port == 53);
}

TEST_CASE("non-IP frames are rejected") {
    test::Bytes arp = FrameBuilder().ethernet(kArp).bytes();
    arp.resize(arp.size() + 28, 0);
    CHECK_FALSE(parse_ethernet(arp.data(), arp.size()));
}

TEST_CASE("IPv6 extension headers are walked to the transport header") {
    const auto frame = FrameBuilder()
                           .ethernet(kIpv6)
                           .ipv6("fe80::1", "2001:db8::2", 0)  // hop-by-hop
                           .ipv6_ext(60)                        // destination options
                           .ipv6_ext(6)                         // -> TCP
                           .tcp(40000, 22, flag::kSyn)
                           .bytes();
    const auto pkt = parse_ethernet(frame.data(), frame.size());
    REQUIRE(pkt);
    CHECK(pkt->transport == Transport::Tcp);
    CHECK(pkt->dst_port == 22);
    CHECK(pkt->is_syn());
}

TEST_CASE("fragments after the first carry no ports") {
    const auto v6_first = FrameBuilder()
                              .ethernet(kIpv6)
                              .ipv6("fd00::1", "2001:db8::2", 44)
                              .ipv6_fragment(17, 0)
                              .udp(1000, 2000)
                              .bytes();
    auto pkt = parse_ethernet(v6_first.data(), v6_first.size());
    REQUIRE(pkt);
    CHECK(pkt->has_ports);
    CHECK(pkt->dst_port == 2000);

    const auto v6_later = FrameBuilder()
                              .ethernet(kIpv6)
                              .ipv6("fd00::1", "2001:db8::2", 44)
                              .ipv6_fragment(17, 185)
                              .udp(1000, 2000)  // really payload bytes
                              .bytes();
    pkt = parse_ethernet(v6_later.data(), v6_later.size());
    REQUIRE(pkt);
    CHECK(pkt->transport == Transport::Udp);
    CHECK_FALSE(pkt->has_ports);

    const auto v4_later = FrameBuilder()
                              .ethernet(kIpv4)
                              .ipv4("192.168.1.2", "203.0.113.1", 6, 0x00B9)
                              .tcp(1, 2, flag::kSyn)
                              .bytes();
    pkt = parse_ethernet(v4_later.data(), v4_later.size());
    REQUIRE(pkt);
    CHECK_FALSE(pkt->has_ports);
    CHECK_FALSE(pkt->is_syn());
}

TEST_CASE("truncated frames never read past caplen") {
    const test::Bytes frames[] = {
        FrameBuilder().ethernet(kIpv4).ipv4("192.168.1.2", "203.0.113.1", 6).tcp(1, 2, 2).bytes(),
        FrameBuilder()
            .ethernet(kIpv4, {kDot1ad, kDot1Q})
            .ipv4("192.168.1.2", "203.0.113.1", 17)
            .udp(1, 2)
            .bytes(),
        FrameBuilder()
            .ethernet(kIpv6, {kDot1Q})
            .ipv6("fd00::1", "2001:db8::2", 0)
            .ipv6_ext(44)
            .ipv6_fragment(6, 0)
            .tcp(1, 2, 2)
            .bytes(),
    };
    for (const auto& frame : frames) {
        // Every prefix must parse without overruns; full parse only at full length.
        for (std::size_t len = 0; len < frame.size(); ++len) {
            CAPTURE(len);
            const auto pkt = parse_prefix(frame, len);
            if (pkt) CHECK_FALSE(pkt->has_ports);
        }
        const auto full = parse_prefix(frame, frame.size());
        REQUIRE(full);
        CHECK(full->has_ports);
    }
}

TEST_CASE("truncated transport header keeps addresses") {
    auto frame =
        FrameBuilder().ethernet(kIpv4).ipv4("192.168.1.2", "203.0.113.1", 6).tcp(1, 2, 2).bytes();
    frame.resize(14 + 20 + 10);  // half a TCP header
    const auto pkt = parse_ethernet(frame.data(), frame.size());
    REQUIRE(pkt);
    CHECK(pkt->src_ip.to_string() == "192.168.1.2");
    CHECK(pkt->transport == Transport::Tcp);
    CHECK_FALSE(pkt->has_ports);
    CHECK_FALSE(pkt->is_syn());
}

TEST_CASE("bad IP headers are rejected") {
    auto bad_ihl =
        FrameBuilder().ethernet(kIpv4).ipv4("192.168.1.2", "203.0.113.1", 6).tcp(1, 2, 2).bytes();
    bad_ihl[14] = 0x44;  // IHL 4 words < 20 bytes
    CHECK_FALSE(parse_ethernet(bad_ihl.data(), bad_ihl.size()));

    auto wrong_version =
        FrameBuilder().ethernet(kIpv6).ipv6("fd00::1", "fd00::2", 6).tcp(1, 2, 2).bytes();
    wrong_version[14] = 0x40;
    CHECK_FALSE(parse_ethernet(wrong_version.data(), wrong_version.size()));
}

TEST_CASE("TCP truncated after the flags byte still counts a SYN") {
    auto frame =
        FrameBuilder().ethernet(kIpv4).ipv4("192.168.1.2", "203.0.113.1", 6).tcp(1, 2, flag::kSyn).bytes();
    frame.resize(14 + 20 + 14);  // flags byte (offset 13) present, header incomplete
    const auto pkt = parse_ethernet(frame.data(), frame.size());
    REQUIRE(pkt);
    CHECK_FALSE(pkt->has_ports);
    CHECK(pkt->is_syn());
    frame.resize(14 + 20 + 13);  // flags byte cut off
    const auto cut = parse_ethernet(frame.data(), frame.size());
    REQUIRE(cut);
    CHECK_FALSE(cut->is_syn());
}

TEST_CASE("three or more VLAN tags are walked, not dropped") {
    const auto frame = FrameBuilder()
                           .ethernet(kIpv4, {kDot1ad, kDot1Q, kDot1Q})
                           .ipv4("192.168.1.12", "203.0.113.102", 6)
                           .tcp(50002, 443, flag::kSyn)
                           .bytes();
    const auto pkt = parse_ethernet(frame.data(), frame.size());
    REQUIRE(pkt);
    CHECK(pkt->src_ip.to_string() == "192.168.1.12");
    CHECK(pkt->dst_port == 443);
    CHECK(pkt->is_syn());
}
