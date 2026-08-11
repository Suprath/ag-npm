#include "file_oracle.hpp"
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

namespace fs = std::filesystem;

namespace aarchgate {

std::string FileOracle::aarchgate_dir() {
    const char* home = std::getenv("HOME");
    return home ? std::string(home) + "/.aarchgate" : "/tmp/.aarchgate";
}

FileOracle::FileOracle(const std::string& oracle_dir) {
    oracle_dir_ = oracle_dir.empty() ? aarchgate_dir() + "/oracle/" : oracle_dir;
    if (oracle_dir_.back() != '/') oracle_dir_ += "/";
    fs::create_directories(oracle_dir_);
}

std::string FileOracle::trace_path(const std::string& integrity_hash) const {
    std::string safe_hash = integrity_hash;
    for (char& c : safe_hash) {
        if (c == '/' || c == '+' || c == '=') c = '_';
    }
    return oracle_dir_ + safe_hash + ".trace";
}

void FileOracle::record(const std::string& integrity_hash, const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    FileAccessRecord rec;
    rec.sequence_no = seq_counter_++;
    rec.path = path;
    traces_[integrity_hash].push_back(rec);
}

void FileOracle::flush_trace(const std::string& integrity_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = traces_.find(integrity_hash);
    if (it == traces_.end()) return;

    std::ofstream out(trace_path(integrity_hash), std::ios::binary);
    for (const auto& rec : it->second) {
        out.write(reinterpret_cast<const char*>(&rec.sequence_no), sizeof(rec.sequence_no));
        uint32_t len = rec.path.size();
        out.write(reinterpret_cast<const char*>(&len), sizeof(len));
        out.write(rec.path.data(), len);
        out.write(reinterpret_cast<const char*>(&rec.offset), sizeof(rec.offset));
        out.write(reinterpret_cast<const char*>(&rec.length), sizeof(rec.length));
    }
}

bool FileOracle::load_trace(const std::string& integrity_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ifstream in(trace_path(integrity_hash), std::ios::binary);
    if (!in) return false;

    std::vector<FileAccessRecord> trace;
    while (in) {
        FileAccessRecord rec;
        if (!in.read(reinterpret_cast<char*>(&rec.sequence_no), sizeof(rec.sequence_no))) break;
        uint32_t len = 0;
        if (!in.read(reinterpret_cast<char*>(&len), sizeof(len))) break;
        rec.path.resize(len);
        if (!in.read(&rec.path[0], len)) break;
        if (!in.read(reinterpret_cast<char*>(&rec.offset), sizeof(rec.offset))) break;
        if (!in.read(reinterpret_cast<char*>(&rec.length), sizeof(rec.length))) break;
        trace.push_back(rec);
    }
    traces_[integrity_hash] = trace;
    return true;
}

void FileOracle::prefetch_for(const std::string& integrity_hash, const std::string& workspace_dir) const {
    std::vector<FileAccessRecord> trace;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = traces_.find(integrity_hash);
        if (it == traces_.end()) return;
        trace = it->second;
    }

    std::string base_dir = workspace_dir;
    if (!base_dir.empty() && base_dir.back() != '/') base_dir += "/";

    for (const auto& rec : trace) {
        std::string path = rec.path;
        if (path.front() == '/') path = path.substr(1);
        std::string full_path = base_dir + path;

        int fd = open(full_path.c_str(), O_RDONLY);
        if (fd < 0) continue;

        // Try to madvise and read 4K to warm page cache
        madvise((void*)0, 0, MADV_SEQUENTIAL); // Note: proper madvise requires mmap, simulating intent here
        char buf[4096];
        read(fd, buf, sizeof(buf));
        close(fd);
    }
}

} // namespace aarchgate
