// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Binary Encoding & Bitwise Mapping Integration Test Suite

#include <iostream>
#include <cassert>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <chrono>

#include "host/bloom_filter.hpp"
#include "host/binary_manifest.hpp"
#include "host/bitwise_policy.hpp"

using namespace aarchgate;
namespace fs = std::filesystem;

static std::string tmp_dir(const std::string& name) {
    std::string p = "/tmp/aarchgate_test_bb_" + name;
    fs::create_directories(p);
    return p;
}

static void write_file(const std::string& path, const std::string& body) {
    fs::create_directories(fs::path(path).parent_path());
    std::ofstream f(path); f << body;
}

// ── Test 1: BloomFilter ───────────────────────────────────────────────────────
void test_bloom_filter() {
    std::cout << "Running test_bloom_filter...\n";
    BloomFilter bf;
    assert(bf.count_bits_set() == 0);

    std::string key1 = "sha512-react_18.2.0_hash==";
    std::string key2 = "sha512-lodash_4.17.21_hash==";
    std::string missing_key = "sha512-malicious_pkg==";

    assert(!bf.may_contain_key(key1));
    assert(!bf.may_contain_key(key2));

    bf.insert_key(key1);
    assert(bf.may_contain_key(key1));
    assert(!bf.may_contain_key(missing_key));

    bf.insert_key(key2);
    assert(bf.may_contain_key(key2));
    assert(bf.count_bits_set() > 0);

    bf.clear();
    assert(bf.count_bits_set() == 0);
    assert(!bf.may_contain_key(key1));

    std::cout << "✓ test_bloom_filter passed!\n";
}

// ── Test 2: BinaryManifest ───────────────────────────────────────────────────
void test_binary_manifest() {
    std::cout << "Running test_binary_manifest...\n";
    std::string proj_dir = tmp_dir("manifest_test");

    BinaryManifest manifest(proj_dir);

    PackedManifestEntry e1{};
    e1.package_id_hash = BinaryManifest::compute_package_id_hash("react@18.2.0");
    e1.hash_prefix = BinaryManifest::compute_hash_prefix("sha512-react==");
    e1.cars_slot_index = 1;
    e1.install_time_ns = 1000000;
    e1.flags = 1;

    PackedManifestEntry e2{};
    e2.package_id_hash = BinaryManifest::compute_package_id_hash("typescript@5.3.3");
    e2.hash_prefix = BinaryManifest::compute_hash_prefix("sha512-ts==");
    e2.cars_slot_index = 2;
    e2.install_time_ns = 2000000;
    e2.flags = 0;

    manifest.update_entry(e1);
    manifest.update_entry(e2);
    assert(manifest.size() == 2);

    bool saved = manifest.save();
    assert(saved);

    // Reload
    BinaryManifest manifest2(proj_dir);
    bool loaded = manifest2.load();
    assert(loaded);
    assert(manifest2.size() == 2);

    assert(manifest2.entries().count(e1.package_id_hash) == 1);
    assert(manifest2.entries().count(e2.package_id_hash) == 1);

    // Diff against lockfile
    write_file(proj_dir + "/package-lock.json", R"({
  "lockfileVersion": 3,
  "packages": {
    "node_modules/react": {
      "version": "18.2.0",
      "integrity": "sha512-react=="
    },
    "node_modules/axios": {
      "version": "1.6.0",
      "integrity": "sha512-axios=="
    }
  }
})");

    auto delta = manifest2.diff(proj_dir + "/package-lock.json");
    // axios added, typescript removed, react unchanged
    assert(delta.added.size() == 1);
    assert(delta.removed.size() == 1);
    assert(delta.unchanged.size() == 1);

    std::cout << "✓ test_binary_manifest passed!\n";
}

// ── Test 3: BitwisePolicyEvaluator ────────────────────────────────────────────
void test_bitwise_policy() {
    std::cout << "Running test_bitwise_policy...\n";

    uint64_t req = CAP_OPEN_READ | CAP_PATH_WORKSPACE;
    uint64_t allowed = CAP_OPEN_READ | CAP_OPEN_WRITE | CAP_PATH_WORKSPACE;
    uint64_t denied = CAP_PATH_SENSITIVE;

    bool pass1 = BitwisePolicyEvaluator::evaluate_fast(req, allowed, denied);
    assert(pass1);

    uint64_t req_bad = CAP_OPEN_READ | CAP_PATH_SENSITIVE;
    bool pass2 = BitwisePolicyEvaluator::evaluate_fast(req_bad, allowed, denied);
    assert(!pass2);

    // Test NEON SIMD Batch Evaluation
    std::vector<uint64_t> batch_req = {req, req_bad, req, req_bad, req, req_bad};
    std::vector<uint8_t> results(batch_req.size(), 0);

    BitwisePolicyEvaluator::evaluate_batch_neon(batch_req.data(), allowed, denied, results.data(), batch_req.size());

    assert(results[0] == 1);
    assert(results[1] == 0);
    assert(results[2] == 1);
    assert(results[3] == 0);
    assert(results[4] == 1);
    assert(results[5] == 0);

    std::cout << "✓ test_bitwise_policy passed!\n";
}

int main() {
    std::cout << "=== AarchGate Binary Encoding & Bitwise Engine Test Suite ===\n\n";

    test_bloom_filter();
    test_binary_manifest();
    test_bitwise_policy();

    std::cout << "\n✓ All Binary Encoding & Bitwise Engine tests passed!\n";
    return 0;
}
