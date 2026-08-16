// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: 64-Bit Capability Bitmask & NEON Vector Evaluator Implementation

#include "host/bitwise_policy.hpp"

namespace aarchgate {

uint64_t BitwisePolicyEvaluator::map_event_to_bitmask(const std::string& event_type, const std::string& target_path) {
    uint64_t mask = CAP_NONE;

    if (event_type == "EVENT_OPEN") {
        mask |= CAP_OPEN_READ;
    } else if (event_type == "EVENT_WRITE") {
        mask |= CAP_OPEN_WRITE;
    } else if (event_type == "EVENT_EXECVE") {
        mask |= CAP_EXECVE;
    } else if (event_type == "EVENT_CONNECT") {
        mask |= CAP_CONNECT_NET;
    } else if (event_type == "EVENT_UNLINK") {
        mask |= CAP_UNLINK;
    }

    if (target_path.find(".ssh") != std::string::npos ||
        target_path.find(".env") != std::string::npos ||
        target_path.find("/etc/") != std::string::npos) {
        mask |= CAP_PATH_SENSITIVE;
    } else if (target_path.find("node_modules") != std::string::npos ||
               target_path.find("/tmp") != std::string::npos) {
        mask |= CAP_PATH_WORKSPACE;
    }

    return mask;
}

void BitwisePolicyEvaluator::evaluate_batch_neon(const uint64_t* requested_masks,
                                                uint64_t allowed_mask,
                                                uint64_t denied_mask,
                                                uint8_t* out_results,
                                                size_t count) {
    uint64x2_t v_allowed = vdupq_n_u64(allowed_mask);
    uint64x2_t v_denied = vdupq_n_u64(denied_mask);
    uint64x2_t v_zero = vdupq_n_u64(0);

    size_t i = 0;
    for (; i + 1 < count; i += 2) {
        uint64x2_t v_req = vld1q_u64(&requested_masks[i]);

        // Check denied bits: (req & denied) == 0
        uint64x2_t v_denied_check = vandq_u64(v_req, v_denied);
        uint64x2_t v_denied_pass = vceqq_u64(v_denied_check, v_zero);

        // Check allowed bits: (req & allowed) == req
        uint64x2_t v_allowed_check = vandq_u64(v_req, v_allowed);
        uint64x2_t v_allowed_pass = vceqq_u64(v_allowed_check, v_req);

        // Final result: denied_pass AND allowed_pass
        uint64x2_t v_pass = vandq_u64(v_denied_pass, v_allowed_pass);

        uint64_t res[2];
        vst1q_u64(res, v_pass);

        out_results[i] = (res[0] == 0xFFFFFFFFFFFFFFFFULL) ? 1 : 0;
        out_results[i + 1] = (res[1] == 0xFFFFFFFFFFFFFFFFULL) ? 1 : 0;
    }

    // Handle tail element
    for (; i < count; ++i) {
        out_results[i] = evaluate_fast(requested_masks[i], allowed_mask, denied_mask) ? 1 : 0;
    }
}

} // namespace aarchgate
