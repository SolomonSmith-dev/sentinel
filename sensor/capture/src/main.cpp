// sentinel-capture: per-host flow metadata in 10 s windows. See README.md.
#include <csignal>
#include <cstdio>
#include <cstdlib>

#include "capture_runner.hpp"
#include "config.hpp"
#include "log.hpp"

namespace {

sentinel::StopFlag g_stop{false};

static_assert(sentinel::StopFlag::is_always_lock_free, "stop flag must be signal-safe");

extern "C" void on_signal(int /*signum*/) { g_stop.store(true); }

void install_signal_handlers() {
    struct sigaction action {};
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    // No SA_RESTART: a blocking read returns early so the loop sees the flag.
    action.sa_flags = 0;
    sigaction(SIGINT, &action, nullptr);
    sigaction(SIGTERM, &action, nullptr);
}

const char* getenv_const(const char* name) { return std::getenv(name); }

}  // namespace

int main(int argc, char** argv) {
    const sentinel::ParseResult parsed = sentinel::parse_config(argc, argv, getenv_const);
    if (!parsed.config) {
        std::fputs(parsed.message.c_str(), parsed.exit_code == 0 ? stdout : stderr);
        return parsed.exit_code;
    }
    const sentinel::Config& cfg = *parsed.config;
    if (cfg.verbose) sentinel::log::set_level(sentinel::log::Level::Debug);

    install_signal_handlers();
    return cfg.replay() ? sentinel::run_replay(cfg, g_stop) : sentinel::run_live(cfg, g_stop);
}
