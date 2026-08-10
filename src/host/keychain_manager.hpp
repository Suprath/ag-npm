// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: macOS Keychain & Hardware Enclave Credential Protection (Wall 3A)

#pragma once

#include <string>
#include <vector>

namespace aarchgate {

struct SecureCredential {
    std::string service;
    std::string account;
    bool is_hardware_protected{true};
};

class KeychainManager {
public:
    KeychainManager() = default;

    // Checks if host credentials (~/.ssh/id_rsa, ~/.npmrc token) are stored in macOS Keychain
    bool is_keychain_protected(const std::string& account) const;

    // Registers a key/token into macOS Keychain with Biometric (TouchID/Secure Enclave) ACL
    bool store_credential(const std::string& service, const std::string& account, const std::string& secret);

    // Queries status of host credential security posture
    std::vector<SecureCredential> audit_host_credentials() const;
};

} // namespace aarchgate
