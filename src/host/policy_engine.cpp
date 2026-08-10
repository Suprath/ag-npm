// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: JIT-Accelerated Sandbox Policy Engine

#include "host/policy_engine.hpp"
#include "apex/jit/ir.hpp"
#include <iostream>
#include <cstring>
#include <algorithm>

namespace aarchgate {

PolicyEngine::PolicyEngine() {
    init_JIT_schema();
}

void PolicyEngine::init_JIT_schema() {
    // 1. Define schema fields matching SyscallTraceRecord layout
    std::vector<apex::core::FieldDescriptor> fields = {
        {"pid",             (uint32_t)offsetof(SyscallTraceRecord, pid),             64, apex::core::DataType::UINT64},
        {"ppid",            (uint32_t)offsetof(SyscallTraceRecord, ppid),            64, apex::core::DataType::UINT64},
        {"event_type",      (uint32_t)offsetof(SyscallTraceRecord, event_type),      64, apex::core::DataType::UINT64},
        {"is_preinstall",   (uint32_t)offsetof(SyscallTraceRecord, is_preinstall),   64, apex::core::DataType::UINT64},
        {"is_sensitive",    (uint32_t)offsetof(SyscallTraceRecord, is_sensitive),    64, apex::core::DataType::UINT64},
        {"is_unauthorized", (uint32_t)offsetof(SyscallTraceRecord, is_unauthorized), 64, apex::core::DataType::UINT64}
    };

    // Stride is exactly 64 bytes
    JIT_engine_.register_schema("SyscallTrace", fields, sizeof(SyscallTraceRecord));

    // 2. Build JIT Policy AST:
    // policy_violation = is_preinstall & ((event_type == 2 /* OPEN */ & is_sensitive) | (event_type == 3 /* CONNECT */ & is_unauthorized))
    using namespace apex::builder;

    auto is_preinstall   = Load("is_preinstall");
    auto event_type      = Load("event_type");
    auto is_sensitive    = Load("is_sensitive");
    auto is_unauthorized = Load("is_unauthorized");

    // Convert fields to BITMASKs by comparing them to Const(1)
    auto is_preinstall_mask   = EQ(is_preinstall, Const(1));
    auto is_sensitive_mask    = EQ(is_sensitive, Const(1));
    auto is_unauthorized_mask = EQ(is_unauthorized, Const(1));

    // Open policy violation check: event_type == EVENT_OPEN (2) AND accessing sensitive path
    auto open_check = And(EQ(event_type, Const(EVENT_OPEN)), is_sensitive_mask);

    // Connect policy violation check: event_type == EVENT_CONNECT (3) AND unauthorized connection
    auto connect_check = And(EQ(event_type, Const(EVENT_CONNECT)), is_unauthorized_mask);

    // Any violation condition
    auto violation_check = Or(open_check, connect_check);

    // Root node: must be spawned under preinstall/lifecycle script AND violate policy
    auto root = And(is_preinstall_mask, violation_check);

    // Compile the AST to native ARM64 machine code
    JIT_engine_.set_expression("SyscallTrace", root, apex::ExecutionMode::BIT_SLICED);
}

static bool is_internal_npm_tool(const std::string& arg) {
    return (arg.find("node-gyp") != std::string::npos ||
            arg.find("node-pre-gyp") != std::string::npos ||
            arg.find("node-gyp-build") != std::string::npos ||
            arg.find("prebuild-install") != std::string::npos);
}

static bool check_is_npm_root(const std::string& comm, const std::string& arg) {
    if (comm.rfind("npm", 0) == 0 || comm.rfind("pnpm", 0) == 0 ||
        comm.rfind("yarn", 0) == 0 || comm.rfind("bun", 0) == 0) {
        return true;
    }
    if (arg.find("npm-cli.js") != std::string::npos || arg.find("bin/npm") != std::string::npos) {
        return true;
    }
    return false;
}

SyscallTraceRecord PolicyEngine::process_event(const SyscallEvent& event) {
    SyscallTraceRecord rec{};
    std::memset(&rec, 0, sizeof(rec));

    total_events_++;

    rec.pid = event.pid;
    rec.ppid = event.ppid;
    rec.event_type = event.event_type;

    std::string comm(event.comm);
    std::string arg(event.arg_str);

    // 1. Process Tree Tracking & Preinstall Inheritance
    bool is_preinstall_process = false;
    {
        std::lock_guard<std::mutex> lock(tree_mutex_);

        auto parent_it = process_tree_.find(event.ppid);
        bool parent_is_untrusted = (parent_it != process_tree_.end()) && parent_it->second.is_preinstall_descendant;
        bool parent_is_npm_root  = (parent_it != process_tree_.end()) && parent_it->second.is_npm_root;

        if (event.event_type == EVENT_EXEC) {
            bool is_npm_root = check_is_npm_root(comm, arg);
            
            bool is_untrusted_script = parent_is_untrusted;
            bool is_lifecycle_hook   = false;

            if (!is_npm_root && !is_untrusted_script) {
                if (is_internal_npm_tool(arg)) {
                    is_untrusted_script = false;
                } else if (parent_is_npm_root || event.ppid > 1) {
                    // Spawned under npm installer (e.g. sh -c "node postinstall.js")
                    is_untrusted_script = true;
                    is_lifecycle_hook   = true;
                } else if (parent_it != process_tree_.end() && parent_it->second.is_lifecycle_hook) {
                    is_untrusted_script = true;
                }
            }

            process_tree_[event.pid] = ProcessNode{
                event.pid, event.ppid, comm, arg, is_npm_root, is_lifecycle_hook, is_untrusted_script
            };
            is_preinstall_process = is_untrusted_script;
        } 
        else if (event.event_type == EVENT_FORK) {
            // Process fork() — child inherits preinstall descendant state instantly
            bool is_untrusted = parent_is_untrusted;
            process_tree_[event.pid] = ProcessNode{
                event.pid, event.ppid, comm, "fork", false, false, is_untrusted
            };
            is_preinstall_process = is_untrusted;
        } 
        else {
            // For OPEN and CONNECT, look up the process's preinstall status
            auto proc_it = process_tree_.find(event.pid);
            if (proc_it != process_tree_.end()) {
                is_preinstall_process = proc_it->second.is_preinstall_descendant;
            } else {
                is_preinstall_process = parent_is_untrusted;
            }
        }
    }

    rec.is_preinstall = is_preinstall_process ? 1 : 0;

    // 2. Policy Classification
    if (event.event_type == EVENT_OPEN) {
        if (arg.find("/proc/") != std::string::npos) proc_reads_++;
        if (arg.find("cgroup") != std::string::npos) cgroup_reads_++;
        if (arg.find("/workspace") != std::string::npos) workspace_reads_++;

        // Wall 2C: Native Addon (.node) dlopen detection
        bool is_native_addon_proc = false;
        {
            std::lock_guard<std::mutex> lock(tree_mutex_);
            auto proc_it = process_tree_.find(event.pid);
            if (arg.find(".node") != std::string::npos && proc_it != process_tree_.end()) {
                proc_it->second.is_native_addon = true;
            }
            if (proc_it != process_tree_.end()) {
                is_native_addon_proc = proc_it->second.is_native_addon;
            }
        }

        // Classify sensitive paths
        // Match credential and config files — covers both /home/user and /root (Alpine default)
        bool has_sensitive_pattern = false;
        if (arg.find(".ssh/")              != std::string::npos ||
            arg.find(".aws/")              != std::string::npos ||
            arg.find("aws/credentials")    != std::string::npos ||
            arg.find(".env")               != std::string::npos ||
            arg.find(".npmrc")             != std::string::npos ||
            arg.find(".gitconfig")         != std::string::npos ||
            arg.find("/etc/passwd")        != std::string::npos ||
            arg.find("/etc/shadow")        != std::string::npos ||
            arg.find("/proc/self/environ") != std::string::npos ||
            (arg.find("/proc/")             != std::string::npos && arg.find("/mem")  != std::string::npos) ||
            (arg.find("/proc/")             != std::string::npos && arg.find("/maps") != std::string::npos) ||
            arg.find("/dev/mem")           != std::string::npos ||
            arg.find("/dev/kmem")          != std::string::npos ||
            arg.find("id_rsa")             != std::string::npos ||
            arg.find("id_ed25519")         != std::string::npos ||
            arg.find("authorized_keys")    != std::string::npos ||
            (is_native_addon_proc && arg.find("/workspace") == std::string::npos && arg.find("/tmp") == std::string::npos)) {
            has_sensitive_pattern = true;
            credential_reads_++;
        }
        rec.is_sensitive = has_sensitive_pattern ? 1 : 0;
    } 
    else if (event.event_type == EVENT_CONNECT) {
        if (event.ip_address == 0) {
            unix_socket_connects_++;
        } else {
            external_ipv4_connects_++;
        }
        // Zero-Trust Outbound Rule: Preinstall scripts have NO business connecting to the internet.
        // Network connections from a preinstall descendant process are flagged as unauthorized.
        rec.is_unauthorized = is_preinstall_process ? 1 : 0;
    }

    if (rec.is_preinstall && ((rec.event_type == EVENT_OPEN && rec.is_sensitive) || (rec.event_type == EVENT_CONNECT && rec.is_unauthorized))) {
        total_violations_++;
    }

    return rec;
}

ForensicsReport PolicyEngine::generate_report() const {
    ForensicsReport report{};
    report.total_events = total_events_.load();
    report.total_violations = total_violations_.load();
    report.proc_reads = proc_reads_.load();
    report.cgroup_reads = cgroup_reads_.load();
    report.credential_reads = credential_reads_.load();
    report.workspace_reads = workspace_reads_.load();
    report.unix_socket_connects = unix_socket_connects_.load();
    report.external_ipv4_connects = external_ipv4_connects_.load();

    uint32_t score = 0;
    if (report.total_violations > 0) score += 80 + static_cast<uint32_t>(report.total_violations * 5);
    if (report.credential_reads > 0) score += 15;
    if (report.external_ipv4_connects > 0) score += 10;
    if (score > 100) score = 100;

    report.risk_score = score;
    if (report.total_violations > 0 || score >= 80) report.verdict = "BLOCKED";
    else if (score >= 40) report.verdict = "SUSPICIOUS";
    else report.verdict = "CLEAN";

    return report;
}

bool PolicyEngine::scan_script_content(const std::string& script_content, std::string& out_reason) const {
    if (script_content.find("eval(") != std::string::npos ||
        script_content.find("Function(") != std::string::npos ||
        script_content.find("vm.runInContext") != std::string::npos) {
        out_reason = "Dynamic code evaluation (eval/Function/vm.runInContext)";
        return false;
    }

    if ((script_content.find("Buffer.from(") != std::string::npos || script_content.find("atob(") != std::string::npos) &&
        (script_content.find("toString('utf8')") != std::string::npos || script_content.find("toString('base64')") != std::string::npos || script_content.find("toString()") != std::string::npos)) {
        out_reason = "Obfuscated Base64 payload decoding pattern";
        return false;
    }

    if (script_content.find(".ssh/") != std::string::npos ||
        script_content.find(".npmrc") != std::string::npos ||
        script_content.find(".aws/credentials") != std::string::npos ||
        script_content.find("id_rsa") != std::string::npos) {
        out_reason = "Hardcoded credential path reference in script";
        return false;
    }

    return true;
}

uint64_t PolicyEngine::evaluate_batch(const SyscallTraceRecord* records, size_t count) {
    if (count == 0) return 0;

    // AarchGate JIT execute runs on row counts.
    // If count < 64, we can evaluate it, but to run in high-performance native bit-sliced mode,
    // the ApexEngine expects multiples of 64 or pads them.
    // Let's call execute, which slices and runs the JIT compiled expression.
    return JIT_engine_.execute(records, count);
}

bool PolicyEngine::is_preinstall_process(uint64_t pid) {
    std::lock_guard<std::mutex> lock(tree_mutex_);
    auto it = process_tree_.find(pid);
    return (it != process_tree_.end()) && it->second.is_preinstall_descendant;
}

void PolicyEngine::register_process(uint64_t pid, uint64_t ppid, const std::string& comm, bool force_preinstall) {
    std::lock_guard<std::mutex> lock(tree_mutex_);
    bool is_npm_root = (comm == "npm" || comm == "pnpm" || comm == "yarn" || comm == "bun");
    process_tree_[pid] = ProcessNode{pid, ppid, comm, "", is_npm_root, false, force_preinstall};
}

void PolicyEngine::register_native_addon(uint64_t pid) {
    std::lock_guard<std::mutex> lock(tree_mutex_);
    auto it = process_tree_.find(pid);
    if (it != process_tree_.end()) {
        it->second.is_native_addon = true;
    }
}

void PolicyEngine::unregister_process(uint64_t pid) {
    std::lock_guard<std::mutex> lock(tree_mutex_);
    process_tree_.erase(pid);
}

} // namespace aarchgate
