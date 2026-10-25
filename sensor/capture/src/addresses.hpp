// Value types for link-layer and network-layer addresses.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

namespace sentinel {

struct MacAddress {
    std::array<std::uint8_t, 6> bytes{};

    std::string to_string() const;

    friend bool operator==(const MacAddress& a, const MacAddress& b) { return a.bytes == b.bytes; }
    friend bool operator!=(const MacAddress& a, const MacAddress& b) { return !(a == b); }
};

// An IPv4 or IPv6 address. IPv4 uses the first four bytes of `bytes`.
class IpAddress {
public:
    enum class Family : std::uint8_t { V4, V6 };

    IpAddress() = default;
    static IpAddress v4(const std::uint8_t* src);
    static IpAddress v6(const std::uint8_t* src);
    // Parses dotted-quad or RFC 4291 text. Throws std::invalid_argument on bad input.
    static IpAddress parse(const std::string& text);

    Family family() const { return family_; }
    const std::array<std::uint8_t, 16>& bytes() const { return bytes_; }

    // True for the address ranges docs/sensor-format.md calls "local":
    // 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, fe80::/10.
    bool is_local() const;

    std::string to_string() const;

    friend bool operator==(const IpAddress& a, const IpAddress& b) {
        return a.family_ == b.family_ && a.bytes_ == b.bytes_;
    }
    friend bool operator!=(const IpAddress& a, const IpAddress& b) { return !(a == b); }
    friend bool operator<(const IpAddress& a, const IpAddress& b) {
        if (a.family_ != b.family_) return a.family_ < b.family_;
        return a.bytes_ < b.bytes_;
    }

private:
    Family family_ = Family::V4;
    std::array<std::uint8_t, 16> bytes_{};
};

namespace detail {
// FNV-1a over a byte range; good enough for hash-map keys of a few bytes.
inline std::size_t fnv1a(const std::uint8_t* data, std::size_t len, std::size_t seed) {
    std::uint64_t h = 14695981039346656037ULL ^ seed;
    for (std::size_t i = 0; i < len; ++i) {
        h ^= data[i];
        h *= 1099511628211ULL;
    }
    return static_cast<std::size_t>(h);
}
}  // namespace detail

}  // namespace sentinel

namespace std {
template <>
struct hash<sentinel::MacAddress> {
    std::size_t operator()(const sentinel::MacAddress& m) const noexcept {
        return sentinel::detail::fnv1a(m.bytes.data(), m.bytes.size(), 0);
    }
};

template <>
struct hash<sentinel::IpAddress> {
    std::size_t operator()(const sentinel::IpAddress& ip) const noexcept {
        return sentinel::detail::fnv1a(ip.bytes().data(), ip.bytes().size(),
                                       static_cast<std::size_t>(ip.family()));
    }
};
}  // namespace std
