#include <doctest/doctest.h>

#include <stdexcept>

#include "addresses.hpp"

using sentinel::IpAddress;

TEST_CASE("local address classification follows the contract") {
    const char* local[] = {"10.0.0.1",       "10.255.255.255", "172.16.0.1",  "172.31.255.254",
                           "192.168.0.1",    "192.168.1.20",   "100.64.0.1",  "100.127.255.255",
                           "fc00::1",        "fd12:3456::1",   "fe80::1",     "febf::ffff"};
    for (const char* text : local) {
        CAPTURE(text);
        CHECK(IpAddress::parse(text).is_local());
    }

    const char* remote[] = {"9.255.255.255", "11.0.0.1",   "172.15.255.255", "172.32.0.1",
                            "192.167.1.1",   "192.169.0.1", "100.63.255.255", "100.128.0.1",
                            "203.0.113.9",   "8.8.8.8",     "2001:db8::1",    "fec0::1",
                            "fe00::1",       "::1",         "ff02::1"};
    for (const char* text : remote) {
        CAPTURE(text);
        CHECK_FALSE(IpAddress::parse(text).is_local());
    }
}

TEST_CASE("addresses round-trip through text") {
    CHECK(IpAddress::parse("192.168.1.20").to_string() == "192.168.1.20");
    CHECK(IpAddress::parse("FE80::0:1").to_string() == "fe80::1");
    CHECK_THROWS_AS(IpAddress::parse("not-an-ip"), std::invalid_argument);
    CHECK(IpAddress::parse("10.0.0.1") != IpAddress::parse("::ffff:10.0.0.1"));
}
