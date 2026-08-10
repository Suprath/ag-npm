// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Policy Engine Unit Tests

#include "src/host/policy_engine.hpp"
#include <cassert>
#include <iostream>
#include <vector>
#include <cstring>

using namespace aarchgate;

void test_process_tree_inheritance() {
    std::cout << "Running test_process_tree_inheritance..." << std::endl;
    PolicyEngine pe;

    // 1. Register a trusted parent process (npm client)
    pe.register_process(100, 1, "npm", false);
    assert(pe.is_preinstall_process(100) == false);

    // 2. Mock execution of an npm preinstall hook process (sh) spawned by npm
    SyscallEvent ev_exec_sh{};
    ev_exec_sh.pid = 101;
    ev_exec_sh.ppid = 100;
    ev_exec_sh.event_type = EVENT_EXEC;
    std::strcpy(ev_exec_sh.comm, "sh");
    std::strcpy(ev_exec_sh.arg_str, "-c node postinstall.js");

    SyscallTraceRecord rec_exec_sh = pe.process_event(ev_exec_sh);
    assert(pe.is_preinstall_process(101) == true);
    assert(rec_exec_sh.is_preinstall == 1);

    // 3. Mock sub-process execution (node executing the malicious script) spawned by sh
    SyscallEvent ev_exec_node{};
    ev_exec_node.pid = 102;
    ev_exec_node.ppid = 101;
    ev_exec_node.event_type = EVENT_EXEC;
    std::strcpy(ev_exec_node.comm, "node");
    std::strcpy(ev_exec_node.arg_str, "postinstall.js");

    SyscallTraceRecord rec_exec_node = pe.process_event(ev_exec_node);
    assert(pe.is_preinstall_process(102) == true);
    assert(rec_exec_node.is_preinstall == 1);

    // 4. Test EVENT_FORK: child process spawned via fork() inherits preinstall state immediately
    SyscallEvent ev_fork_child{};
    ev_fork_child.pid = 103;
    ev_fork_child.ppid = 102;
    ev_fork_child.event_type = EVENT_FORK;
    std::strcpy(ev_fork_child.comm, "node");
    std::strcpy(ev_fork_child.arg_str, "fork");

    SyscallTraceRecord rec_fork_child = pe.process_event(ev_fork_child);
    assert(pe.is_preinstall_process(103) == true);
    assert(rec_fork_child.is_preinstall == 1);

    // 5. Test internal npm tool allowlist (e.g. node-gyp build)
    SyscallEvent ev_nodegyp{};
    ev_nodegyp.pid = 104;
    ev_nodegyp.ppid = 100;
    ev_nodegyp.event_type = EVENT_EXEC;
    std::strcpy(ev_nodegyp.comm, "node");
    std::strcpy(ev_nodegyp.arg_str, "/usr/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js");

    SyscallTraceRecord rec_nodegyp = pe.process_event(ev_nodegyp);
    assert(pe.is_preinstall_process(104) == false);
    assert(rec_nodegyp.is_preinstall == 0);

    std::cout << "✓ test_process_tree_inheritance passed!" << std::endl;
}

void test_policy_classification_and_jit_evaluation() {
    std::cout << "Running test_policy_classification_and_jit_evaluation..." << std::endl;
    PolicyEngine pe;

    // Register a preinstall script process (PID 101)
    pe.register_process(101, 100, "node", true);

    // Create a batch of 64 records for AarchGate JIT evaluation
    std::vector<SyscallTraceRecord> batch(64);
    for (size_t i = 0; i < 64; ++i) {
        batch[i].pid = 200 + i;
        batch[i].ppid = 200;
        batch[i].event_type = EVENT_OPEN;
        batch[i].is_preinstall = 0;
        batch[i].is_sensitive = 0;
        batch[i].is_unauthorized = 0;
    }

    // 1. Safe Event: Preinstall script opening a project file
    SyscallEvent ev_safe_open{};
    ev_safe_open.pid = 101;
    ev_safe_open.ppid = 100;
    ev_safe_open.event_type = EVENT_OPEN;
    std::strcpy(ev_safe_open.comm, "node");
    std::strcpy(ev_safe_open.arg_str, "/var/www/project/node_modules/lodash/index.js");

    SyscallTraceRecord rec_safe_open = pe.process_event(ev_safe_open);
    assert(rec_safe_open.is_preinstall == 1);
    assert(rec_safe_open.is_sensitive == 0);
    assert(rec_safe_open.is_unauthorized == 0);

    // Feed safe open to batch
    batch[0] = rec_safe_open;

    uint64_t violation_mask = pe.evaluate_batch(batch.data(), 64);
    assert(violation_mask == 0);

    // 2. Malicious Event: Preinstall script opening .ssh/id_rsa
    SyscallEvent ev_ssh_open{};
    ev_ssh_open.pid = 101;
    ev_ssh_open.ppid = 100;
    ev_ssh_open.event_type = EVENT_OPEN;
    std::strcpy(ev_ssh_open.comm, "node");
    std::strcpy(ev_ssh_open.arg_str, "/Users/suprathps/.ssh/id_rsa");

    SyscallTraceRecord rec_ssh_open = pe.process_event(ev_ssh_open);
    assert(rec_ssh_open.is_preinstall == 1);
    assert(rec_ssh_open.is_sensitive == 1);
    assert(rec_ssh_open.is_unauthorized == 0);

    // Feed malicious SSH read to index 32 of batch
    batch[32] = rec_ssh_open;

    uint64_t violation_count = pe.evaluate_batch(batch.data(), 64);
    assert(violation_count == 1);

    // Reset batch[32] to safe
    batch[32].is_sensitive = 0;

    // 3. Malicious Event: Preinstall script opening socket to exfiltrate
    SyscallEvent ev_connect{};
    ev_connect.pid = 101;
    ev_connect.ppid = 100;
    ev_connect.event_type = EVENT_CONNECT;
    std::strcpy(ev_connect.comm, "node");
    std::strcpy(ev_connect.arg_str, "connect");
    ev_connect.ip_address = 0x08080808; // 8.8.8.8
    ev_connect.port = 443;

    SyscallTraceRecord rec_connect = pe.process_event(ev_connect);
    assert(rec_connect.is_preinstall == 1);
    assert(rec_connect.is_sensitive == 0);
    assert(rec_connect.is_unauthorized == 1);

    // Feed connect to index 5
    batch[5] = rec_connect;

    violation_count = pe.evaluate_batch(batch.data(), 64);
    assert(violation_count == 1);
    std::cout << "✓ test_policy_classification_and_jit_evaluation passed!" << std::endl;
}

void test_static_script_analyzer() {
    std::cout << "Running test_static_script_analyzer..." << std::endl;
    PolicyEngine pe;
    std::string reason;

    std::string safe_script = "console.log('Building native addon...');";
    assert(pe.scan_script_content(safe_script, reason) == true);

    std::string eval_script = "eval(Buffer.from('Li5zc2gvaWRfcnNh', 'base64').toString('utf8'));";
    assert(pe.scan_script_content(eval_script, reason) == false);
    assert(!reason.empty());

    std::string cred_script = "const key = fs.readFileSync('/root/.ssh/id_rsa');";
    assert(pe.scan_script_content(cred_script, reason) == false);

    std::cout << "✓ test_static_script_analyzer passed!" << std::endl;
}

int main() {
    std::cout << "=== AarchGate Sandbox Policy Engine Tests ===" << std::endl;
    test_process_tree_inheritance();
    test_policy_classification_and_jit_evaluation();
    test_static_script_analyzer();
    std::cout << "✓ All policy engine tests passed!" << std::endl;
    return 0;
}
