// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Persistent Audit Log Manager Implementation

#include "host/audit_log.hpp"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <random>

namespace aarchgate {

static std::string generate_session_id() {
    static const char chars[] = "0123456789abcdef";
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 15);
    std::string id;
    for (int i = 0; i < 8; ++i) id += chars[dist(rng)];
    return id;
}

AuditLog::AuditLog(const std::string& pkg_name, const std::string& pkg_version)
    : session_id_(generate_session_id()), pkg_name_(pkg_name), pkg_version_(pkg_version) {
    
    // Determine user home directory or default audit path
    const char* home = std::getenv("HOME");
    std::filesystem::path audit_dir = home ? (std::filesystem::path(home) / ".aarchgate" / "audit") : "/tmp/aarchgate_audit";
    
    std::error_code ec;
    std::filesystem::create_directories(audit_dir, ec);

    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y%m%dT%H%M%S");
    
    std::string filename = ss.str() + "_" + session_id_ + ".ndjson";
    log_path_ = audit_dir / filename;

    log_file_.open(log_path_, std::ios::out | std::ios::app);
}

AuditLog::~AuditLog() {
    if (log_file_.is_open()) {
        log_file_.flush();
        log_file_.close();
    }
}

std::string AuditLog::current_timestamp_iso() const {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    auto timer = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&timer), "%Y-%m-%dT%H:%M:%S")
       << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    return ss.str();
}

void AuditLog::log_session_start(const std::string& kernel, const std::string& initrd) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!log_file_.is_open()) return;

    log_file_ << "{\"type\":\"SESSION_START\","
              << "\"timestamp\":\"" << current_timestamp_iso() << "\","
              << "\"session_id\":\"" << session_id_ << "\","
              << "\"package\":\"" << pkg_name_ << "\","
              << "\"version\":\"" << pkg_version_ << "\","
              << "\"kernel\":\"" << kernel << "\","
              << "\"initrd\":\"" << initrd << "\"}\n";
    log_file_.flush();
}

void AuditLog::log_event(const MonitorEvent& ev) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!log_file_.is_open()) return;

    std::string event_name = "UNKNOWN";
    if (ev.event_type == EVENT_EXEC) event_name = "EXEC";
    else if (ev.event_type == EVENT_OPEN) event_name = "OPEN";
    else if (ev.event_type == EVENT_CONNECT) event_name = "CONNECT";
    else if (ev.event_type == EVENT_FORK) event_name = "FORK";
    else if (ev.event_type == EVENT_MTE_TRAP) event_name = "MTE_TRAP";
    else if (ev.event_type == EVENT_VM_STATE_CHANGE) event_name = "VM_STATE_CHANGE";

    log_file_ << "{\"type\":\"EVENT\","
              << "\"timestamp\":\"" << current_timestamp_iso() << "\","
              << "\"event_type\":\"" << event_name << "\","
              << "\"pid\":" << ev.pid << ","
              << "\"ppid\":" << ev.ppid << ","
              << "\"comm\":\"" << ev.comm << "\","
              << "\"arg\":\"" << ev.arg_str << "\","
              << "\"is_preinstall\":" << (ev.is_preinstall ? "true" : "false") << ","
              << "\"is_sensitive\":" << (ev.is_sensitive ? "true" : "false") << ","
              << "\"is_unauthorized\":" << (ev.is_unauthorized ? "true" : "false") << "}\n";
    log_file_.flush();
}

void AuditLog::log_violation(const MonitorEvent& ev, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!log_file_.is_open()) return;

    log_file_ << "{\"type\":\"VIOLATION\","
              << "\"timestamp\":\"" << current_timestamp_iso() << "\","
              << "\"pid\":" << ev.pid << ","
              << "\"comm\":\"" << ev.comm << "\","
              << "\"arg\":\"" << ev.arg_str << "\","
              << "\"reason\":\"" << reason << "\"}\n";
    log_file_.flush();
}

void AuditLog::log_session_end(bool killed_by_policy, uint64_t total_violations) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!log_file_.is_open()) return;

    log_file_ << "{\"type\":\"SESSION_END\","
              << "\"timestamp\":\"" << current_timestamp_iso() << "\","
              << "\"killed_by_policy\":" << (killed_by_policy ? "true" : "false") << ","
              << "\"total_violations\":" << total_violations << "}\n";
    log_file_.flush();
}

} // namespace aarchgate
