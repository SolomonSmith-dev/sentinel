#include <doctest/doctest.h>

#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "frame_builder.hpp"
#include "window_aggregator.hpp"
#include "window_clock.hpp"

using nlohmann::json;
using sentinel::Transport;
using sentinel::WindowAggregator;
using test::packet;
namespace flag = sentinel::tcp_flag;

namespace {

std::vector<json> lines(const std::string& ndjson) {
    std::vector<json> out;
    std::istringstream in(ndjson);
    for (std::string line; std::getline(in, line);) out.push_back(json::parse(line));
    return out;
}

}  // namespace

TEST_CASE("packets with no local side are ignored") {
    WindowAggregator agg;
    agg.add(packet("203.0.113.1", "198.51.100.2", 1, 2, Transport::Tcp, 1, 2), 60);
    CHECK(agg.host_count() == 0);
    CHECK(agg.packet_count() == 0);
}

TEST_CASE("outbound and inbound attribution with SYN accounting") {
    WindowAggregator agg;
    agg.add(packet("192.168.1.20", "203.0.113.9", 0x14, 0xFE, Transport::Tcp, 5000, 443,
                   flag::kSyn),
            54);
    agg.add(packet("203.0.113.9", "192.168.1.20", 0xFE, 0x14, Transport::Tcp, 443, 5000,
                   flag::kSyn | flag::kAck),
            60);
    agg.add(packet("192.168.1.20", "203.0.113.9", 0x14, 0xFE, Transport::Tcp, 5000, 443,
                   flag::kAck),
            54);

    const auto out = lines(agg.to_ndjson(1761370750, 10, "eth0"));
    REQUIRE(out.size() == 1);
    const json& h = out[0];
    CHECK(h["window_start"] == 1761370750);
    CHECK(h["window_s"] == 10);
    CHECK(h["iface"] == "eth0");
    CHECK(h["host"]["mac"] == "02:00:00:00:00:14");
    CHECK(h["host"]["ip"] == "192.168.1.20");
    CHECK(h["pkts_out"] == 2);
    CHECK(h["pkts_in"] == 1);
    CHECK(h["bytes_out"] == 108);
    CHECK(h["bytes_in"] == 60);
    CHECK(h["syn_out"] == 1);
    CHECK(h["synack_in"] == 1);
    CHECK(h["distinct_dests"] == 1);
    CHECK(h["distinct_ports_out"] == 1);
    CHECK(h["dests"][0] == json{{"ip", "203.0.113.9"}, {"pkts", 2}, {"bytes", 108}, {"syn", 1},
                                {"ports", {443}}});
    CHECK(h["inbound_sources"][0] ==
          json{{"ip", "203.0.113.9"}, {"pkts", 1}, {"syn", 0}, {"distinct_ports", 1}});
}

TEST_CASE("output keys follow the contract order") {
    WindowAggregator agg;
    agg.add(packet("192.168.1.2", "203.0.113.1", 2, 1, Transport::Udp, 1, 53), 60);
    const std::string line = agg.to_ndjson(0, 10, "eth0");
    const std::vector<std::string> keys = {
        "window_start", "window_s", "iface",     "host",           "pkts_out",
        "pkts_in",      "bytes_out", "bytes_in", "syn_out",        "synack_in",
        "distinct_dests", "distinct_ports_out", "dests", "inbound_sources"};
    std::size_t pos = 0;
    for (const auto& key : keys) {
        const std::size_t found = line.find("\"" + key + "\"", pos);
        CAPTURE(key);
        REQUIRE(found != std::string::npos);
        pos = found;
    }
}

TEST_CASE("local-to-local packets count for both hosts") {
    WindowAggregator agg;
    agg.add(packet("192.168.1.10", "192.168.1.11", 0x0A, 0x0B, Transport::Other, 0, 0), 98);
    REQUIRE(agg.host_count() == 2);
    CHECK(agg.packet_count() == 1);
    const auto out = lines(agg.to_ndjson(0, 10, "eth0"));
    REQUIRE(out.size() == 2);
    CHECK(out[0]["host"]["ip"] == "192.168.1.10");  // sorted by MAC
    CHECK(out[0]["pkts_out"] == 1);
    CHECK(out[0]["distinct_ports_out"] == 0);       // no ports for non-TCP/UDP
    CHECK(out[0]["dests"][0]["ports"] == json::array());
    CHECK(out[1]["pkts_in"] == 1);
    CHECK(out[1]["bytes_in"] == 98);
}

TEST_CASE("broadcast frames do not create a host") {
    WindowAggregator agg;
    auto p = packet("192.168.1.10", "192.168.1.255", 0x0A, 0xFF, Transport::Udp, 137, 137);
    p.dst_mac.bytes = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    agg.add(p, 92);
    CHECK(agg.host_count() == 1);  // only the sender
}

TEST_CASE("caps apply to lists but not to distinct counts") {
    WindowAggregator agg;
    // 300 remotes, the first with 100 ports, plus 70 inbound sources.
    for (int r = 0; r < 300; ++r) {
        const std::string ip = "203.0." + std::to_string(r / 250) + "." + std::to_string(r % 250);
        const int ports = r == 0 ? 100 : 1;
        for (int p = 0; p < ports; ++p) {
            agg.add(packet("10.0.0.5", ip.c_str(), 5, 1, Transport::Tcp, 40000,
                           static_cast<std::uint16_t>(1 + p), flag::kSyn),
                    54);
        }
    }
    for (int s = 0; s < 70; ++s) {
        const std::string ip = "198.51.100." + std::to_string(s);
        agg.add(packet(ip.c_str(), "10.0.0.5", 1, 5, Transport::Udp, 53, 9999), 60);
    }

    const auto out = lines(agg.to_ndjson(0, 10, "eth0"));
    REQUIRE(out.size() == 1);
    const json& h = out[0];
    CHECK(h["distinct_dests"] == 300);
    CHECK(h["distinct_ports_out"] == 100);
    CHECK(h["dests"].size() == 256);
    CHECK(h["dests"][0]["ip"] == "203.0.0.0");  // most packets first
    CHECK(h["dests"][0]["pkts"] == 100);
    CHECK(h["dests"][0]["ports"].size() == 64);
    CHECK(h["dests"][0]["ports"][0] == 1);
    CHECK(h["dests"][0]["ports"][63] == 64);
    CHECK(h["inbound_sources"].size() == 64);
}

TEST_CASE("window_of floors to 10 s boundaries") {
    using sentinel::window_of;
    CHECK(window_of(1761370750) == 1761370750);
    CHECK(window_of(1761370759) == 1761370750);
    CHECK(window_of(1761370760) == 1761370760);
    CHECK(window_of(-1) == -10);
}
