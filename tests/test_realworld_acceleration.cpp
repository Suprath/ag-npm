// (c) 2026 Suprath PS. All rights reserved.
// AarchGate Real-World Build Acceleration Test Suite (v3.1.0)

#include <iostream>
#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>

#include "host/cars.hpp"
#include "host/parallel_extractor.hpp"
#include "host/fsevent_watcher.hpp"

using namespace aarchgate;
using namespace std::chrono;
namespace fs = std::filesystem;

static std::string make_tmp_dir(const std::string& prefix) {
    std::string path = "/tmp/ag_test_realworld_" + prefix + "_" + std::to_string(duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count());
    fs::create_directories(path);
    return path;
}

// ── Test 1: APFS Reflink Directory Cloning ──────────────────────────────────
void test_apfs_reflink_cloning() {
    std::cout << "Running test_apfs_reflink_cloning..." << std::endl;

    std::string root = make_tmp_dir("cars_apfs");
    ContentAddressableStore store(root);

    // Create a mock package slot with 100 files
    std::string pkg_src = make_tmp_dir("pkg_src");
    for (int i = 0; i < 100; ++i) {
        std::ofstream out(pkg_src + "/file_" + std::to_string(i) + ".js");
        out << "console.log('mock package content " << i << "');\n";
    }

    std::string hash = "sha512-mock_apfs_reflink_pkg==";
    store.put(hash, pkg_src);

    // Test clone_into
    std::string dest_dir = make_tmp_dir("pkg_dest");
    auto t0 = steady_clock::now();
    bool cloned = store.clone_into(hash, dest_dir);
    auto t1 = steady_clock::now();

    double elapsed_us = duration_cast<microseconds>(t1 - t0).count();
    assert(cloned);
    assert(fs::exists(dest_dir + "/file_0.js"));
    assert(fs::exists(dest_dir + "/file_99.js"));

    std::cout << "✓ test_apfs_reflink_cloning passed! (Cloned 100 files in " << elapsed_us << " µs)" << std::endl;

    fs::remove_all(root);
    fs::remove_all(pkg_src);
    fs::remove_all(dest_dir);
}

// ── Test 2: Multi-Core SIMD Parallel Tarball Extractor ─────────────────────
void test_parallel_extractor() {
    std::cout << "Running test_parallel_extractor..." << std::endl;

    std::string test_dir = make_tmp_dir("parallel_extract");
    
    // Create 5 dummy tarball archives
    std::vector<ExtractionTask> tasks;
    for (int i = 0; i < 5; ++i) {
        std::string src_folder = test_dir + "/src_" + std::to_string(i);
        fs::create_directories(src_folder);
        std::ofstream out(src_folder + "/index.js");
        out << "module.exports = 'test_" << i << "';\n";

        std::string tar_path = test_dir + "/archive_" + std::to_string(i) + ".tgz";
        std::string cmd = "tar -czf \"" + tar_path + "\" -C \"" + src_folder + "\" index.js";
        int res = std::system(cmd.c_str());
        assert(res == 0);

        ExtractionTask t;
        t.archive_path = tar_path;
        t.target_dir = test_dir + "/dest_" + std::to_string(i);
        tasks.push_back(t);
    }

    // Execute batch extraction
    auto results = ParallelExtractor::extract_batch(tasks);
    assert(results.size() == 5);
    for (int i = 0; i < 5; ++i) {
        assert(results[i].success);
        assert(fs::exists(tasks[i].target_dir + "/index.js"));
    }

    std::cout << "✓ test_parallel_extractor passed! (5 archives extracted concurrently)" << std::endl;

    fs::remove_all(test_dir);
}

int main() {
    std::cout << "=== AarchGate Real-World Build Acceleration Test Suite (v3.1.0) ===" << std::endl;
    test_apfs_reflink_cloning();
    test_parallel_extractor();
    std::cout << "\n✓ All Real-World Build Acceleration tests passed!" << std::endl;
    return 0;
}
