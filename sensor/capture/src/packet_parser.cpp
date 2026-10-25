#include "packet_parser.hpp"

#include <cstring>

namespace sentinel {
namespace {

constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86DD;
constexpr std::uint16_t kEtherTypeVlan = 0x8100;   // 802.1Q
constexpr std::uint16_t kEtherTypeQinQ = 0x88A8;   // 802.1ad outer tag
constexpr int kMaxVlanTags = 2;

constexpr std::uint8_t kProtoTcp = 6;
constexpr std::uint8_t kProtoUdp = 17;

constexpr std::size_t kEthernetHeaderLen = 14;
constexpr std::size_t kVlanTagLen = 4;
constexpr std::size_t kIpv4MinHeaderLen = 20;
constexpr std::size_t kIpv6HeaderLen = 40;
constexpr std::size_t kTcpMinHeaderLen = 20;
constexpr std::size_t kUdpHeaderLen = 8;

// IPv6 extension headers we walk past to find the transport header.
constexpr std::uint8_t kIpv6HopByHop = 0;
constexpr std::uint8_t kIpv6Routing = 43;
constexpr std::uint8_t kIpv6Fragment = 44;
constexpr std::uint8_t kIpv6Auth = 51;
constexpr std::uint8_t kIpv6DestOpts = 60;
constexpr std::uint8_t kIpv6Mobility = 135;
constexpr int kMaxIpv6ExtHeaders = 8;  // bounds the walk on hostile chains

// A bounds-checked view over the captured bytes.
class ByteCursor {
public:
    ByteCursor(const std::uint8_t* data, std::size_t len) : data_(data), len_(len) {}

    bool has(std::size_t offset, std::size_t n) const {
        return offset <= len_ && n <= len_ - offset;
    }
    std::uint8_t u8(std::size_t offset) const { return data_[offset]; }
    std::uint16_t u16(std::size_t offset) const {
        return static_cast<std::uint16_t>((data_[offset] << 8) | data_[offset + 1]);
    }
    const std::uint8_t* at(std::size_t offset) const { return data_ + offset; }

private:
    const std::uint8_t* data_;
    std::size_t len_;
};

// Fills ports and flags if the full transport header fits in the capture.
void parse_transport(const ByteCursor& cur, std::size_t offset, std::uint8_t proto,
                     PacketInfo& pkt) {
    if (proto == kProtoTcp) {
        pkt.transport = Transport::Tcp;
        if (!cur.has(offset, kTcpMinHeaderLen)) return;
        pkt.src_port = cur.u16(offset);
        pkt.dst_port = cur.u16(offset + 2);
        pkt.tcp_flags = cur.u8(offset + 13);
        pkt.has_ports = true;
    } else if (proto == kProtoUdp) {
        pkt.transport = Transport::Udp;
        if (!cur.has(offset, kUdpHeaderLen)) return;
        pkt.src_port = cur.u16(offset);
        pkt.dst_port = cur.u16(offset + 2);
        pkt.has_ports = true;
    }
}

bool parse_ipv4(const ByteCursor& cur, std::size_t offset, PacketInfo& pkt) {
    if (!cur.has(offset, kIpv4MinHeaderLen)) return false;
    const std::uint8_t version = cur.u8(offset) >> 4;
    const std::size_t ihl = static_cast<std::size_t>(cur.u8(offset) & 0x0F) * 4;
    if (version != 4 || ihl < kIpv4MinHeaderLen) return false;

    pkt.src_ip = IpAddress::v4(cur.at(offset + 12));
    pkt.dst_ip = IpAddress::v4(cur.at(offset + 16));

    // Only the first fragment carries the transport header.
    const std::uint16_t frag_offset = cur.u16(offset + 6) & 0x1FFF;
    if (frag_offset != 0) {
        const std::uint8_t proto = cur.u8(offset + 9);
        pkt.transport = proto == kProtoTcp   ? Transport::Tcp
                        : proto == kProtoUdp ? Transport::Udp
                                             : Transport::Other;
        return true;
    }
    parse_transport(cur, offset + ihl, cur.u8(offset + 9), pkt);
    return true;
}

bool parse_ipv6(const ByteCursor& cur, std::size_t offset, PacketInfo& pkt) {
    if (!cur.has(offset, kIpv6HeaderLen)) return false;
    if ((cur.u8(offset) >> 4) != 6) return false;

    pkt.src_ip = IpAddress::v6(cur.at(offset + 8));
    pkt.dst_ip = IpAddress::v6(cur.at(offset + 24));

    std::uint8_t next = cur.u8(offset + 6);
    std::size_t pos = offset + kIpv6HeaderLen;
    for (int i = 0; i < kMaxIpv6ExtHeaders; ++i) {
        switch (next) {
            case kIpv6HopByHop:
            case kIpv6Routing:
            case kIpv6DestOpts:
            case kIpv6Mobility: {
                if (!cur.has(pos, 2)) return true;  // addresses are still useful
                next = cur.u8(pos);
                pos += (static_cast<std::size_t>(cur.u8(pos + 1)) + 1) * 8;
                continue;
            }
            case kIpv6Auth: {
                if (!cur.has(pos, 2)) return true;
                next = cur.u8(pos);
                pos += (static_cast<std::size_t>(cur.u8(pos + 1)) + 2) * 4;
                continue;
            }
            case kIpv6Fragment: {
                if (!cur.has(pos, 8)) return true;
                next = cur.u8(pos);
                const std::uint16_t frag_offset = cur.u16(pos + 2) >> 3;
                pos += 8;
                if (frag_offset != 0) {
                    pkt.transport = next == kProtoTcp   ? Transport::Tcp
                                    : next == kProtoUdp ? Transport::Udp
                                                        : Transport::Other;
                    return true;
                }
                continue;
            }
            default:
                parse_transport(cur, pos, next, pkt);
                return true;
        }
    }
    return true;  // chain too long: keep the addresses, drop the ports
}

}  // namespace

std::optional<PacketInfo> parse_ethernet(const std::uint8_t* data, std::size_t caplen) {
    const ByteCursor cur(data, caplen);
    if (!cur.has(0, kEthernetHeaderLen)) return std::nullopt;

    PacketInfo pkt;
    std::memcpy(pkt.dst_mac.bytes.data(), cur.at(0), 6);
    std::memcpy(pkt.src_mac.bytes.data(), cur.at(6), 6);

    std::size_t offset = 12;
    std::uint16_t ether_type = cur.u16(offset);
    for (int tags = 0; (ether_type == kEtherTypeVlan || ether_type == kEtherTypeQinQ) &&
                       tags < kMaxVlanTags;
         ++tags) {
        offset += kVlanTagLen;
        if (!cur.has(offset, 2)) return std::nullopt;
        ether_type = cur.u16(offset);
    }
    offset += 2;

    bool ok = false;
    if (ether_type == kEtherTypeIpv4) {
        ok = parse_ipv4(cur, offset, pkt);
    } else if (ether_type == kEtherTypeIpv6) {
        ok = parse_ipv6(cur, offset, pkt);
    }
    if (!ok) return std::nullopt;
    return pkt;
}

}  // namespace sentinel
