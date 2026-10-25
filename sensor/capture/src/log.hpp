// Minimal leveled logging to stderr. Info and above must never contain IPs or MACs.
#pragma once

#include <string>

namespace sentinel::log {

enum class Level { Debug = 0, Info = 1, Warn = 2, Error = 3 };

void set_level(Level level);
bool enabled(Level level);
void write(Level level, const std::string& message);

inline void debug(const std::string& m) { write(Level::Debug, m); }
inline void info(const std::string& m) { write(Level::Info, m); }
inline void warn(const std::string& m) { write(Level::Warn, m); }
inline void error(const std::string& m) { write(Level::Error, m); }

}  // namespace sentinel::log
