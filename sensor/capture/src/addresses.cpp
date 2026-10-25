#include "addresses.hpp"

#include <arpa/inet.h>

#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace sentinel {

std::string MacAddress::to_string() const {
    char buf[18];
    std::snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1],
                  bytes[2], bytes[3], bytes[4], bytes[5]);
    return buf;
}

IpAddress IpAddress::v4(const std::uint8_t* src) {
    IpAddress ip;
    ip.family_ = Family::V4;
    std::memcpy(ip.bytes_.data(), src, 4);
    return ip;
}

IpAddress IpAddress::v6(const std::uint8_t* src) {
    IpAddress ip;
    ip.family_ = Family::V6;
    std::memcpy(ip.bytes_.data(), src, 16);
    return ip;
}

IpAddress IpAddress::parse(const std::string& text) {
    std::array<std::uint8_t, 16> buf{};
    if (inet_pton(AF_INET, text.c_str(), buf.data()) == 1) return v4(buf.data());
    if (inet_pton(AF_INET6, text.c_str(), buf.data()) == 1) return v6(buf.data());
    throw std::invalid_argument("not an IP address: " + text);
}

bool IpAddress::is_local() const {
    const auto& b = bytes_;
    if (family_ == Family::V4) {
        return b[0] == 10                                    // 10.0.0.0/8
               || (b[0] == 172 && (b[1] & 0xF0) == 16)       // 172.16.0.0/12
               || (b[0] == 192 && b[1] == 168)               // 192.168.0.0/16
               || (b[0] == 100 && (b[1] & 0xC0) == 64);      // 100.64.0.0/10 (CGNAT)
    }
    return (b[0] & 0xFE) == 0xFC                             // fc00::/7 (ULA)
           || (b[0] == 0xFE && (b[1] & 0xC0) == 0x80);       // fe80::/10 (link-local)
}

std::string IpAddress::to_string() const {
    char buf[INET6_ADDRSTRLEN];
    const int af = family_ == Family::V4 ? AF_INET : AF_INET6;
    if (inet_ntop(af, bytes_.data(), buf, sizeof buf) == nullptr) return "?";
    return buf;
}

}  // namespace sentinel
