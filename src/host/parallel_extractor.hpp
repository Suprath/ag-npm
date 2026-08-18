// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Multi-Core SIMD Tarball Extractor (GCD + Hardware Parallel Decompression)

#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace aarchgate {

struct ExtractionTask {
    std::string archive_path; // Path to local .tgz archive file
    std::string target_dir;   // Destination CARS slot directory
    std::string integrity_hash;
};

struct ExtractionResult {
    std::string archive_path;
    std::string target_dir;
    bool success{false};
    uint64_t bytes_extracted{0};
    double elapsed_ms{0.0};
    std::string error_message;
};

class ParallelExtractor {
public:
    ParallelExtractor() = default;

    // Extract a single tarball archive to target_dir
    static ExtractionResult extract_one(const ExtractionTask& task);

    // Extract multiple tarballs concurrently across CPU performance cores via GCD dispatch_apply
    static std::vector<ExtractionResult> extract_batch(const std::vector<ExtractionTask>& tasks);
};

} // namespace aarchgate
