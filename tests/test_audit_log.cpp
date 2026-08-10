// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Audit Log Unit Tests

#include "src/host/audit_log.hpp"
#include <cassert>
#include <iostream>
#include <fstream>
#include <filesystem>

using namespace aarchgate;

void test_audit_log_creation_and_events() {
    std::cout << "Running test_audit_log_creation_and_events..." << std::endl;

    {
        AuditLog logger("test_pkg", "1.2.3");
        logger.log_session_start("vmlinuz.img", "initrd.img");

        MonitorEvent ev{};
        ev.event_type = EVENT_OPEN;
        ev.pid = 1234;
        ev.ppid = 1000;
        std::strcpy(ev.comm, "node");
        std::strcpy(ev.arg_str, "/workspace/package.json");
        ev.is_preinstall = 1;
        ev.is_sensitive = 0;
        ev.is_unauthorized = 0;

        logger.log_event(ev);

        MonitorEvent viol{};
        viol.event_type = EVENT_OPEN;
        viol.pid = 1234;
        viol.ppid = 1000;
        std::strcpy(viol.comm, "node");
        std::strcpy(viol.arg_str, "/root/.ssh/id_rsa");
        viol.is_preinstall = 1;
        viol.is_sensitive = 1;

        logger.log_violation(viol, "Sensitive file read attempt");
        logger.log_session_end(true, 1);

        assert(std::filesystem::exists(logger.log_path()));
        
        std::ifstream file(logger.log_path());
        std::string line;
        int line_count = 0;
        while (std::getline(file, line)) {
            line_count++;
            assert(!line.empty());
            assert(line.front() == '{' && line.back() == '}');
        }
        assert(line_count == 4); // SESSION_START, EVENT, VIOLATION, SESSION_END
    }

    std::cout << "✓ test_audit_log_creation_and_events passed!" << std::endl;
}

int main() {
    std::cout << "=== AarchGate Audit Log Unit Tests ===" << std::endl;
    test_audit_log_creation_and_events();
    std::cout << "✓ All audit log tests passed!" << std::endl;
    return 0;
}
