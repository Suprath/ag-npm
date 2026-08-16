// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: 64-Bit Capability Bitmask & Fast-Path Evaluator
// Enables 1-cycle policy evaluation and ARM64 NEON SIMD vectorization.

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <arm_neon.h>

namespace aarchgate {

enum CapabilityBit : uint64_t {
    CAP_NONE            = 0,
    CAP_OPEN_READ       = 1ULL << 0,
    CAP_OPEN_WRITE      = 1ULL << 1,
    CAP_EXECVE          = 1ULL << 2,
    CAP_CONNECT_NET     = 1ULL << 3,
    CAP_UNLINK          = 1ULL << 4,
    CAP_PATH_SENSITIVE  = 1ULL << 5, // /etc, ~/.ssh, ~/.env
    CAP_PATH_WORKSPACE  = 1ULL << 6, // node_modules, /tmpfs
    CAP_ALL             = 0xFFFFFFFFFFFFFFFFULL
};

struct BitwiseRule {
    uint64_t allowed_mask;
    uint64_t denied_mask;
};

class BitwisePolicyEvaluator {
public:
    BitwisePolicyEvaluator() = default;

    // Single-cycle evaluation (sub-0.3ns)
    static inline bool evaluate_fast(uint64_t requested_mask, uint64_t allowed_mask, uint64_t denied_mask) {
        if (requested_mask & denied_mask) return false;
        return (requested_mask & allowed_mask) == requested_mask;
    }

    // Convert string event type and target path to a 64-bit capability bitmask
    static uint64_t map_event_to_bitmask(const std::string& event_type, const std::string& target_path);

    // Vector batch evaluation across 64 records using ARM64 NEON SIMD instructions
    static void evaluate_batch_neon(const uint64_t* requested_masks,
                                    uint64_t allowed_mask,
                                    uint64_t denied_mask,
                                    uint8_t* out_results,
                                    size_t count);
};

} // namespace aarchgate
