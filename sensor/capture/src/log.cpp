#include "log.hpp"

#include <atomic>
#include <cstdio>

namespace sentinel::log {
namespace {

std::atomic<Level> g_level{Level::Info};

const char* level_name(Level level) {
    switch (level) {
        case Level::Debug: return "debug";
        case Level::Info: return "info";
        case Level::Warn: return "warn";
        case Level::Error: return "error";
    }
    return "?";
}

}  // namespace

void set_level(Level level) { g_level.store(level); }

bool enabled(Level level) { return level >= g_level.load(); }

void write(Level level, const std::string& message) {
    if (!enabled(level)) return;
    // One fprintf per line keeps lines intact when stderr is shared.
    std::fprintf(stderr, "sentinel-capture %s: %s\n", level_name(level), message.c_str());
}

}  // namespace sentinel::log
