// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Pre-Install Package Reputation & Provenance Scorer (Wall 1A)

#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace aarchgate {

struct PackageMetadata {
    std::string name;
    std::string version;
    std::string author;
    uint32_t age_days{0};
    bool has_install_scripts{false};
    bool has_sigstore_provenance{false};
    uint64_t file_count{0};
    uint64_t total_size_bytes{0};
};

struct CapabilityPolicy {
    bool allow_network{false};
    std::vector<std::string> allowed_paths;
    std::vector<std::string> allowed_executables;
    bool is_strict{true};
};

struct ReputationResult {
    uint32_t score{100}; // 0 = dangerous, 100 = safe
    std::string verdict; // "PASS", "FLAGGED", "REJECT"
    std::vector<std::string> risk_factors;
};

struct HotPathDecision {
    bool eligible;
    std::string reason; // why eligible or why not
};

class ReputationScorer {
public:
    ReputationScorer() = default;

    // Returns true if the package is safe to serve from CARS without a new VM scan.
    // Conditions: CARS hit + prior clean scan + integrity hash unchanged + reputation score >= 80
    HotPathDecision is_hot_path_eligible(const PackageMetadata& meta,
                               const std::string& integrity_hash,
                               bool cars_hit,
                               uint32_t reputation_threshold = 80) const;

    ReputationResult score_package(const PackageMetadata& meta) const;
    CapabilityPolicy load_capability_policy(const std::string& manifest_json_path) const;
};

} // namespace aarchgate
