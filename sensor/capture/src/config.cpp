#include "config.hpp"

#include <string_view>

namespace sentinel {
namespace {

constexpr const char* kDefaultWindowsDir = "/var/lib/sentinel/windows";
constexpr const char* kReplayIfaceName = "pcap";

constexpr const char* kUsage =
    "usage: sentinel-capture --iface <name> [--out <dir>]\n"
    "       sentinel-capture --pcap <file> [--iface <label>] [--out <dir>]\n"
    "\n"
    "  --iface <name>  interface to capture (env SENTINEL_IFACE)\n"
    "  --out <dir>     window output directory (env SENTINEL_WINDOWS_DIR,\n"
    "                  default /var/lib/sentinel/windows)\n"
    "  --pcap <file>   replay a capture file using its packet timestamps\n"
    "  --verbose       debug logging\n";

std::string env_or(const char* (*getenv)(const char*), const char* name,
                   const std::string& fallback) {
    const char* value = getenv(name);
    return (value != nullptr && *value != '\0') ? std::string(value) : fallback;
}

ParseResult usage_error(const std::string& why) {
    return {std::nullopt, 2, "sentinel-capture: " + why + "\n" + kUsage};
}

}  // namespace

ParseResult parse_config(int argc, const char* const* argv,
                         const char* (*getenv)(const char*)) {
    Config cfg;
    std::optional<std::string> iface_flag;
    std::optional<std::string> out_flag;

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        const auto value = [&](std::optional<std::string>& slot) -> bool {
            if (i + 1 >= argc) return false;
            slot = argv[++i];
            return true;
        };
        if (arg == "--help" || arg == "-h") return {std::nullopt, 0, kUsage};
        if (arg == "--verbose" || arg == "-v") {
            cfg.verbose = true;
        } else if (arg == "--iface") {
            if (!value(iface_flag)) return usage_error("--iface needs a value");
        } else if (arg == "--out") {
            if (!value(out_flag)) return usage_error("--out needs a value");
        } else if (arg == "--pcap") {
            std::optional<std::string> pcap;
            if (!value(pcap)) return usage_error("--pcap needs a value");
            cfg.pcap_file = *pcap;
        } else {
            return usage_error("unknown argument '" + std::string(arg) + "'");
        }
    }

    cfg.out_dir = out_flag ? *out_flag : env_or(getenv, "SENTINEL_WINDOWS_DIR", kDefaultWindowsDir);
    if (cfg.replay()) {
        // The env interface describes the live sensor, not a replayed file.
        cfg.iface = iface_flag ? *iface_flag : kReplayIfaceName;
    } else {
        cfg.iface = iface_flag ? *iface_flag : env_or(getenv, "SENTINEL_IFACE", "");
        if (cfg.iface.empty()) return usage_error("no interface: pass --iface or set SENTINEL_IFACE");
    }
    return {cfg, 0, ""};
}

}  // namespace sentinel
