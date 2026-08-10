// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Phase 2 Multi-Wall Defense Unit Tests

#include "src/host/policy_engine.hpp"
#include "src/host/reputation_scorer.hpp"
#include <cassert>
#include <iostream>
#include <vector>

using namespace aarchgate;

void test_package_reputation_scorer() {
    std::cout << "Running test_package_reputation_scorer..." << std::endl;

    ReputationScorer scorer;

    // 1. Safe package with Sigstore provenance
    PackageMetadata safe_pkg{};
    safe_pkg.name = "express";
    safe_pkg.version = "4.18.2";
    safe_pkg.age_days = 365;
    safe_pkg.has_install_scripts = false;
    safe_pkg.has_sigstore_provenance = true;
    safe_pkg.file_count = 120;

    ReputationResult safe_res = scorer.score_package(safe_pkg);
    assert(safe_res.score >= 90);
    assert(safe_res.verdict == "PASS");

    // 2. Suspicious newly published package with install scripts & no provenance
    PackageMetadata suspicious_pkg{};
    suspicious_pkg.name = "evil-test-pkg";
    suspicious_pkg.version = "1.0.0";
    suspicious_pkg.age_days = 2;
    suspicious_pkg.has_install_scripts = true;
    suspicious_pkg.has_sigstore_provenance = false;
    suspicious_pkg.file_count = 10;

    ReputationResult susp_res = scorer.score_package(suspicious_pkg);
    assert(susp_res.score < 50);
    assert(susp_res.verdict == "REJECT");
    assert(susp_res.risk_factors.size() >= 3);

    std::cout << "✓ test_package_reputation_scorer passed!" << std::endl;
}

void test_native_addon_policy_enforcement() {
    std::cout << "Running test_native_addon_policy_enforcement..." << std::endl;

    PolicyEngine pe;
    pe.register_process(500, 100, "node", false);

    // Mock loading of a native .node addon
    SyscallEvent ev_dlopen{};
    ev_dlopen.pid = 500;
    ev_dlopen.ppid = 100;
    ev_dlopen.event_type = EVENT_OPEN;
    std::strcpy(ev_dlopen.comm, "node");
    std::strcpy(ev_dlopen.arg_str, "/workspace/node_modules/bcrypt/build/Release/bcrypt_lib.node");

    pe.process_event(ev_dlopen);

    // Now native addon process tries to open /etc/passwd (outside workspace)
    SyscallEvent ev_native_read{};
    ev_native_read.pid = 500;
    ev_native_read.ppid = 100;
    ev_native_read.event_type = EVENT_OPEN;
    std::strcpy(ev_native_read.comm, "node");
    std::strcpy(ev_native_read.arg_str, "/etc/passwd");

    SyscallTraceRecord rec = pe.process_event(ev_native_read);
    assert(rec.is_sensitive == 1); // Enforced as sensitive/blocked for native addon context

    std::cout << "✓ test_native_addon_policy_enforcement passed!" << std::endl;
}

int main() {
    std::cout << "=== AarchGate Phase 2 Multi-Wall Security Tests ===" << std::endl;
    test_package_reputation_scorer();
    test_native_addon_policy_enforcement();
    std::cout << "✓ All Phase 2 security tests passed!" << std::endl;
    return 0;
}
