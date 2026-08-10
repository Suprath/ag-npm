// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Phase 3 Host Hardening Unit Tests

#include "src/host/keychain_manager.hpp"
#include "src/host/egress_firewall.hpp"
#include <cassert>
#include <iostream>

using namespace aarchgate;

void test_keychain_manager() {
    std::cout << "Running test_keychain_manager..." << std::endl;

    KeychainManager keychain;
    auto creds = keychain.audit_host_credentials();
    assert(creds.size() == 3);
    assert(creds[0].service == "SSH");
    assert(creds[1].service == "NPM");

    std::cout << "✓ test_keychain_manager passed!" << std::endl;
}

void test_egress_firewall() {
    std::cout << "Running test_egress_firewall..." << std::endl;

    EgressFirewall firewall;
    bool enabled = firewall.enable_npm_scoped_isolation();
    assert(enabled == true);
    assert(firewall.is_active() == true);

    bool disabled = firewall.disable_isolation();
    assert(disabled == true);
    assert(firewall.is_active() == false);

    std::cout << "✓ test_egress_firewall passed!" << std::endl;
}

int main() {
    std::cout << "=== AarchGate Phase 3 Host Hardening Security Tests ===" << std::endl;
    test_keychain_manager();
    test_egress_firewall();
    std::cout << "✓ All Phase 3 security tests passed!" << std::endl;
    return 0;
}
