#include <doctest/doctest.h>

#include <map>
#include <string>
#include <vector>

#include "config.hpp"

using sentinel::parse_config;

namespace {

std::map<std::string, std::string> g_env;

const char* fake_getenv(const char* name) {
    const auto it = g_env.find(name);
    return it == g_env.end() ? nullptr : it->second.c_str();
}

sentinel::ParseResult parse(std::vector<const char*> args) {
    args.insert(args.begin(), "sentinel-capture");
    return parse_config(static_cast<int>(args.size()), args.data(), fake_getenv);
}

}  // namespace

TEST_CASE("live mode reads interface and output dir from flags or env") {
    g_env.clear();
    auto r = parse({"--iface", "eth0"});
    REQUIRE(r.config);
    CHECK_FALSE(r.config->replay());
    CHECK(r.config->iface == "eth0");
    CHECK(r.config->out_dir == "/var/lib/sentinel/windows");

    g_env = {{"SENTINEL_IFACE", "enp3s0"}, {"SENTINEL_WINDOWS_DIR", "/tmp/w"}};
    r = parse({});
    REQUIRE(r.config);
    CHECK(r.config->iface == "enp3s0");
    CHECK(r.config->out_dir == "/tmp/w");

    r = parse({"--iface", "eth1", "--out", "/data"});  // flags win
    REQUIRE(r.config);
    CHECK(r.config->iface == "eth1");
    CHECK(r.config->out_dir == "/data");
}

TEST_CASE("replay mode does not need an interface") {
    g_env = {{"SENTINEL_IFACE", "enp3s0"}};
    const auto r = parse({"--pcap", "x.pcap", "--out", "o"});
    REQUIRE(r.config);
    CHECK(r.config->replay());
    CHECK(r.config->iface == "pcap");
}

TEST_CASE("bad arguments exit 2, help exits 0") {
    g_env.clear();
    CHECK(parse({}).exit_code == 2);
    CHECK(parse({"--iface"}).exit_code == 2);
    CHECK(parse({"--bogus"}).exit_code == 2);
    const auto help = parse({"--help"});
    CHECK_FALSE(help.config);
    CHECK(help.exit_code == 0);
}
