#include "window_writer.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <system_error>
#include <utility>

namespace sentinel {
namespace {

[[noreturn]] void throw_errno(const std::string& what) {
    throw std::system_error(errno, std::generic_category(), what);
}

// Owns a POSIX file descriptor; closes it on scope exit.
class UniqueFd {
public:
    explicit UniqueFd(int fd) : fd_(fd) {}
    ~UniqueFd() {
        if (fd_ >= 0) ::close(fd_);
    }
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    int get() const { return fd_; }
    // Closes explicitly so the caller can observe the error.
    int release_and_close() { return ::close(std::exchange(fd_, -1)); }

private:
    int fd_;
};

void write_all(int fd, const std::string& data, const std::string& path) {
    const char* p = data.data();
    std::size_t left = data.size();
    while (left > 0) {
        const ssize_t n = ::write(fd, p, left);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw_errno("write " + path);
        }
        p += n;
        left -= static_cast<std::size_t>(n);
    }
}

}  // namespace

WindowWriter::WindowWriter(std::string out_dir) : out_dir_(std::move(out_dir)) {
    std::filesystem::create_directories(out_dir_);
}

void WindowWriter::write(std::int64_t window_start, const std::string& ndjson) const {
    const std::string final_path = out_dir_ + "/" + std::to_string(window_start) + ".ndjson";
    const std::string tmp_path = final_path + ".tmp";

    UniqueFd fd(::open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
    if (fd.get() < 0) throw_errno("open " + tmp_path);
    write_all(fd.get(), ndjson, tmp_path);
    if (::fsync(fd.get()) != 0) throw_errno("fsync " + tmp_path);
    if (fd.release_and_close() != 0) throw_errno("close " + tmp_path);

    if (std::rename(tmp_path.c_str(), final_path.c_str()) != 0) {
        throw_errno("rename " + tmp_path);
    }
}

}  // namespace sentinel
