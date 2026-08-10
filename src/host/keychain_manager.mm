// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: macOS Keychain Manager Implementation

#include "host/keychain_manager.hpp"
#include <iostream>

#if defined(__APPLE__)
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#endif

namespace aarchgate {

bool KeychainManager::is_keychain_protected(const std::string& account) const {
#if defined(__APPLE__)
    NSDictionary* query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: [NSString stringWithUTF8String:account.c_str()],
        (__bridge id)kSecReturnData: @NO
    };
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, NULL);
    return (status == errSecSuccess);
#else
    (void)account;
    return false;
#endif
}

bool KeychainManager::store_credential(const std::string& service, const std::string& account, const std::string& secret) {
#if defined(__APPLE__)
    NSData* secretData = [NSData dataWithBytes:secret.data() length:secret.size()];
    NSDictionary* query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: [NSString stringWithUTF8String:service.c_str()],
        (__bridge id)kSecAttrAccount: [NSString stringWithUTF8String:account.c_str()],
        (__bridge id)kSecValueData: secretData
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    return (status == errSecSuccess);
#else
    (void)service; (void)account; (void)secret;
    return false;
#endif
}

std::vector<SecureCredential> KeychainManager::audit_host_credentials() const {
    std::vector<SecureCredential> creds;
    creds.push_back(SecureCredential{"SSH", "id_rsa", is_keychain_protected("id_rsa")});
    creds.push_back(SecureCredential{"NPM", "npm_auth_token", is_keychain_protected("npm_auth_token")});
    creds.push_back(SecureCredential{"AWS", "aws_access_key", is_keychain_protected("aws_access_key")});
    return creds;
}

} // namespace aarchgate
