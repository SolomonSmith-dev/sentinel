// End-to-end tests: replay each committed fixture through the real binary and
// check the published window files. Expected values are derived in
// sensor/tests/make_fixtures.py; the arithmetic is spelled out next to each.
#include <doctest/doctest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using nlohmann::json;

namespace {

constexpr long long kT0 = 1761370750;

// Temp directory removed on scope exit.
class TempDir {
public:
    explicit TempDir(const std::string& name)
        : path_(fs::temp_directory_path() / ("sentinel-test-" + name)) {
        fs::remove_all(path_);
        fs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    const fs::path& path() const { return path_; }

private:
    fs::path path_;
};

// window_start -> host lines keyed by host IP.
using Windows = std::map<long long, std::map<std::string, json>>;

Windows replay(const std::string& fixture) {
    const TempDir dir(fixture);
    const std::string cmd = std::string("\"") + SENTINEL_CAPTURE_BIN + "\" --pcap \"" +
                            SENTINEL_FIXTURE_DIR + "/" + fixture + ".pcap\" --out \"" +
                            dir.path().string() + "\"";
    REQUIRE(std::system(cmd.c_str()) == 0);

    Windows windows;
    for (const auto& entry : fs::directory_iterator(dir.path())) {
        const fs::path& p = entry.path();
        REQUIRE_MESSAGE(p.extension() == ".ndjson", "stray file: " << p);  // no .tmp left
        auto& hosts = windows[std::stoll(p.stem().string())];
        std::ifstream in(p);
        for (std::string line; std::getline(in, line);) {
            const json j = json::parse(line);
            CHECK(j["window_s"] == 10);
            CHECK(j["iface"] == "pcap");
            hosts[j["host"]["ip"].get<std::string>()] = j;
        }
    }
    return windows;
}

}  // namespace

TEST_CASE("port_scan") {
    const Windows windows = replay("port_scan");
    REQUIRE(windows.size() == 1);
    REQUIRE(windows.count(kT0) == 1);
    const auto& hosts = windows.at(kT0);
    REQUIRE(hosts.size() == 2);

    SUBCASE("victim: one remote hit 100 distinct ports with SYNs") {
        const json& v = hosts.at("192.168.1.20");
        CHECK(v["host"]["mac"] == "02:00:5e:00:00:14");
        CHECK(v["pkts_in"] == 100);
        CHECK(v["bytes_in"] == 100 * 54);
        CHECK(v["pkts_out"] == 0);
        CHECK(v["distinct_dests"] == 0);
        REQUIRE(v["inbound_sources"].size() == 1);
        const json& src = v["inbound_sources"][0];
        CHECK(src["ip"] == "203.0.113.9");
        CHECK(src["pkts"] == 100);
        CHECK(src["syn"] == 100);
        CHECK(src["distinct_ports"] == 100);
    }

    SUBCASE("scanner: 50 SYNs to 50 ports on one remote, 2 answered") {
        const json& s = hosts.at("192.168.1.30");
        CHECK(s["pkts_out"] == 50);
        CHECK(s["pkts_in"] == 50);
        CHECK(s["syn_out"] == 50);
        CHECK(s["synack_in"] == 2);
        CHECK(s["distinct_dests"] == 1);
        CHECK(s["distinct_ports_out"] == 50);
        REQUIRE(s["dests"].size() == 1);
        CHECK(s["dests"][0]["ip"] == "198.51.100.7");
        CHECK(s["dests"][0]["syn"] == 50);
        CHECK(s["dests"][0]["ports"].size() == 50);
        CHECK(s["inbound_sources"][0]["syn"] == 0);  // SYN-ACK and RST-ACK are not SYNs
    }
}

TEST_CASE("syn_flood") {
    const Windows windows = replay("syn_flood");
    REQUIRE(windows.size() == 1);
    const auto& hosts = windows.at(kT0);
    REQUIRE(hosts.size() == 1);
    const json& v = hosts.at("192.168.1.40");
    CHECK(v["pkts_in"] == 800);
    CHECK(v["bytes_in"] == 800 * 54);
    CHECK(v["pkts_out"] == 0);
    CHECK(v["synack_in"] == 0);
    REQUIRE(v["inbound_sources"].size() == 1);
    const json& src = v["inbound_sources"][0];
    CHECK(src["ip"] == "203.0.113.50");
    CHECK(src["pkts"] == 800);
    CHECK(src["syn"] == 800);
    CHECK(src["distinct_ports"] == 1);
}

TEST_CASE("benign") {
    const Windows windows = replay("benign");
    REQUIRE(windows.size() == 6);

    // Per window, per host: DNS query (74 B) + reply (106 B); TCP 443 session of
    // 7 out (SYN, ACK, 3x 200 B data, FIN, ACK) and 5 in (SYN-ACK, 3x 1200 B
    // data, FIN). Header-only frames are 54 B, data frames 254 / 1254 B.
    // A and B also exchange one 98 B ICMP echo. C is VLAN tagged (+4 B/frame).
    struct Expected {
        int pkts_out, pkts_in, bytes_out, bytes_in, distinct_dests;
    };
    const std::map<std::string, Expected> per_window = {
        {"192.168.1.10", {9, 7, 1150, 4074, 3}},
        {"192.168.1.11", {9, 7, 1150, 4074, 3}},
        {"192.168.1.12", {8, 6, 1084, 4000, 2}},
    };

    std::map<std::string, Expected> totals;
    long long expected_start = kT0;
    for (const auto& [start, hosts] : windows) {
        CHECK(start == expected_start);
        expected_start += 10;
        REQUIRE(hosts.size() == 3);
        for (const auto& [ip, want] : per_window) {
            const std::string host_ip = ip;  // CAPTURE cannot bind structured bindings in C++17
            const long long window = start;
            CAPTURE(host_ip);
            CAPTURE(window);
            const json& h = hosts.at(ip);
            CHECK(h["pkts_out"] == want.pkts_out);
            CHECK(h["pkts_in"] == want.pkts_in);
            CHECK(h["bytes_out"] == want.bytes_out);
            CHECK(h["bytes_in"] == want.bytes_in);
            CHECK(h["syn_out"] == 1);
            CHECK(h["synack_in"] == 1);
            CHECK(h["distinct_dests"] == want.distinct_dests);
            CHECK(h["distinct_ports_out"] == 2);  // 53 and 443
            auto& t = totals[ip];
            t.pkts_out += h["pkts_out"].get<int>();
            t.pkts_in += h["pkts_in"].get<int>();
            t.bytes_out += h["bytes_out"].get<int>();
            t.bytes_in += h["bytes_in"].get<int>();
        }
    }

    // 60 s totals.
    CHECK(totals["192.168.1.10"].pkts_out == 54);
    CHECK(totals["192.168.1.10"].pkts_in == 42);
    CHECK(totals["192.168.1.10"].bytes_out == 6900);
    CHECK(totals["192.168.1.10"].bytes_in == 24444);
    CHECK(totals["192.168.1.12"].pkts_out == 48);
    CHECK(totals["192.168.1.12"].pkts_in == 36);
    CHECK(totals["192.168.1.12"].bytes_out == 6504);
    CHECK(totals["192.168.1.12"].bytes_in == 24000);

    // Local-to-local: B appears as an inbound source of A and vice versa.
    const json& a = windows.at(kT0).at("192.168.1.10");
    bool saw_b = false;
    for (const json& src : a["inbound_sources"]) saw_b |= src["ip"] == "192.168.1.11";
    CHECK(saw_b);
}
