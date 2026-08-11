// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: eBPF File-Access Oracle — Predictive Prefetch Engine (T2)
// Records ordered file access sequences per package; on warm installs,
// prefetches all pages before the VM starts to eliminate cold page faults.

#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <cstdint>

namespace aarchgate {

struct FileAccessRecord {
    uint32_t sequence_no;
    std::string path;
    uint64_t offset{0};
    uint32_t length{0};
};

class FileOracle {
public:
    explicit FileOracle(const std::string& oracle_dir = "");

    // Called from policy_engine on every EVENT_OPEN during a cold install.
    // Associates the file access with the current package being installed.
    void record(const std::string& integrity_hash, const std::string& path);

    // Prefetch all known file access patterns for a package into OS page cache
    // using mmap(MAP_POPULATE) + madvise(MADV_SEQUENTIAL).
    // Call before VM boot for warm installs.
    void prefetch_for(const std::string& integrity_hash, const std::string& workspace_dir) const;

    // Persist the access trace to disk so it survives daemon restarts
    void flush_trace(const std::string& integrity_hash);

    // Load a previously saved trace from disk
    bool load_trace(const std::string& integrity_hash);

private:
    std::string oracle_dir_;  // ~/.aarchgate/oracle/
    mutable std::mutex mutex_;
    // Map from integrity_hash to ordered access sequence
    std::unordered_map<std::string, std::vector<FileAccessRecord>> traces_;
    uint32_t seq_counter_{0};

    std::string trace_path(const std::string& integrity_hash) const;
    static std::string aarchgate_dir();
};

} // namespace aarchgate
