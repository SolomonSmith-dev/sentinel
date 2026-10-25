// Atomic publication of window files for the shipper.
#pragma once

#include <cstdint>
#include <string>

namespace sentinel {

class WindowWriter {
public:
    explicit WindowWriter(std::string out_dir);

    // Writes `<out_dir>/<window_start>.ndjson.tmp`, fsyncs it, then renames it to
    // `<window_start>.ndjson`, so a reader never sees a partial file.
    // Throws std::system_error on I/O failure.
    void write(std::int64_t window_start, const std::string& ndjson) const;

    const std::string& out_dir() const { return out_dir_; }

private:
    std::string out_dir_;
};

}  // namespace sentinel
