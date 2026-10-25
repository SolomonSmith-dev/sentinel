// Command-line and environment configuration.
#pragma once

#include <optional>
#include <string>

namespace sentinel {

struct Config {
    std::string iface;          // live interface; also the "iface" field in output
    std::string out_dir;        // where window files are published
    std::string pcap_file;      // replay mode when non-empty
    bool verbose = false;       // enables debug logging

    bool replay() const { return !pcap_file.empty(); }
};

struct ParseResult {
    std::optional<Config> config;  // empty when the program should exit
    int exit_code = 0;
    std::string message;           // usage or error text for stderr
};

// Flags win over environment: SENTINEL_IFACE, SENTINEL_WINDOWS_DIR.
// `getenv` is injectable for tests.
ParseResult parse_config(int argc, const char* const* argv,
                         const char* (*getenv)(const char*));

}  // namespace sentinel
