// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Pre-Install Package Reputation Scorer Implementation

#include "host/reputation_scorer.hpp"
#include <fstream>
#include <iostream>

namespace aarchgate {

ReputationResult ReputationScorer::score_package(const PackageMetadata& meta) const {
    ReputationResult res{};
    uint32_t score = 100;

    // 1. Install script risk factor
    if (meta.has_install_scripts) {
        score -= 20;
        res.risk_factors.push_back("Package contains lifecycle install scripts (postinstall/preinstall)");
    }

    // 2. Package age risk factor
    if (meta.age_days < 7) {
        score -= 40;
        res.risk_factors.push_back("Package was published less than 7 days ago (high squatting risk)");
    } else if (meta.age_days < 30) {
        score -= 15;
        res.risk_factors.push_back("Package was published less than 30 days ago");
    }

    // 3. Sigstore provenance verification
    if (!meta.has_sigstore_provenance) {
        score -= 10;
        res.risk_factors.push_back("Package lacks Sigstore build provenance signature");
    }

    // 4. File count / size anomalies
    if (meta.file_count > 5000) {
        score -= 15;
        res.risk_factors.push_back("Abnormally high file count in package distribution");
    }

    res.score = score;
    if (score >= 80) {
        res.verdict = "PASS";
    } else if (score >= 50) {
        res.verdict = "FLAGGED";
    } else {
        res.verdict = "REJECT";
    }

    return res;
}

CapabilityPolicy ReputationScorer::load_capability_policy(const std::string& manifest_path) const {
    CapabilityPolicy policy{};
    std::ifstream f(manifest_path);
    if (!f.is_open()) {
        policy.is_strict = true;
        policy.allow_network = false;
        policy.allowed_paths.push_back("/workspace/");
        policy.allowed_paths.push_back("/tmp/");
        return policy;
    }

    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (content.find("\"allow_network\": true") != std::string::npos) {
        policy.allow_network = true;
    }

    policy.allowed_paths.push_back("/workspace/");
    policy.allowed_paths.push_back("/tmp/");
    return policy;
}

HotPathDecision ReputationScorer::is_hot_path_eligible(const PackageMetadata& meta,
                                                       const std::string& integrity_hash,
                                                       bool cars_hit,
                                                       uint32_t reputation_threshold) const {
    HotPathDecision decision;
    decision.eligible = false;
    
    if (!cars_hit) {
        decision.reason = "Not a CARS hit";
        return decision;
    }
    
    ReputationResult res = score_package(meta);
    if (res.score < reputation_threshold) {
        decision.reason = "Reputation score below threshold";
        return decision;
    }
    
    if (!meta.has_sigstore_provenance && res.score < 90) {
        decision.reason = "Missing sigstore provenance and score below 90";
        return decision;
    }
    
    decision.eligible = true;
    decision.reason = "Eligible for hot path";
    return decision;
}

} // namespace aarchgate
