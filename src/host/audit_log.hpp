// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Persistent Audit Log Manager (NDJSON)

#pragma once

#include "common/monitor_protocol.h"
#include <string>
#include <fstream>
#include <mutex>
#include <filesystem>

namespace aarchgate {

class AuditLog {
public:
    AuditLog(const std::string& pkg_name = "sandbox_workspace", const std::string& pkg_version = "1.0.0");
    ~AuditLog();

    void log_session_start(const std::string& kernel, const std::string& initrd);
    void log_event(const MonitorEvent& ev);
    void log_violation(const MonitorEvent& ev, const std::string& reason);
    void log_session_end(bool killed_by_policy, uint64_t total_violations);

    std::string session_id() const { return session_id_; }
    std::filesystem::path log_path() const { return log_path_; }

private:
    std::string           session_id_;
    std::string           pkg_name_;
    std::string           pkg_version_;
    std::filesystem::path log_path_;
    std::ofstream         log_file_;
    std::mutex            mutex_;

    std::string current_timestamp_iso() const;
};

} // namespace aarchgate
