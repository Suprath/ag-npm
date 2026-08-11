// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: NEON/CommonCrypto Hardware-Accelerated SHA-512 Integrity Verifier (T5)

#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace aarchgate {

struct PackageIntegrity {
    std::string name;
    std::string version;
    std::string integrity_hash; // "sha512-<base64>" format from package-lock.json
    std::string tarball_path;   // path to the local .tgz file if present
};

struct IntegrityResult {
    bool valid;
    std::string name;
    std::string version;
    std::string expected_hash;
    std::string actual_hash;
    std::string failure_reason;
};

class IntegrityVerifier {
public:
    IntegrityVerifier() = default;

    // Verify a single package's SHA-512 integrity (CommonCrypto hardware SHA)
    IntegrityResult verify_one(const PackageIntegrity& pkg) const;

    // Verify all packages in parallel using GCD dispatch_apply
    // Returns false and populates failures if any hash mismatch found
    bool verify_all(const std::vector<PackageIntegrity>& packages,
                    std::vector<IntegrityResult>& failures) const;

    // Parse package-lock.json at path and extract PackageIntegrity entries
    static std::vector<PackageIntegrity> parse_lockfile(const std::string& lockfile_path);

private:
    // Compute SHA-512 of data buffer using CommonCrypto (hardware accelerated)
    static std::string sha512_hex(const uint8_t* data, size_t len);
    static std::string sha512_base64(const uint8_t* data, size_t len);
    static std::string read_file(const std::string& path, size_t& out_size);
};

} // namespace aarchgate
