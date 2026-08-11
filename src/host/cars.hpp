// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Content-Addressable RAM Store (CARS) — T1
// Stores extracted package file trees in POSIX shared memory keyed by SHA-512 integrity hash.

#pragma once
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <cstdint>
#include <functional>

namespace aarchgate {

struct CARSEntry {
    std::string integrity_hash;   // sha512-base64 key
    std::string slot_path;        // ~/.aarchgate/cars/<hash>/ directory
    uint64_t size_bytes{0};
    uint64_t install_time_ns{0};
    uint32_t hit_count{0};
};

class ContentAddressableStore {
public:
    explicit ContentAddressableStore(const std::string& store_root = "");

    // Check if a package is in the store
    bool contains(const std::string& integrity_hash) const;

    // Get the on-disk slot path for a cached package (to mmap into VM workspace)
    // Returns empty string if not present
    std::string get_slot_path(const std::string& integrity_hash) const;

    // Store a package directory tree from source_dir into CARS
    // Returns the slot_path
    std::string put(const std::string& integrity_hash, const std::string& source_dir);

    // Copy a CARS slot into a destination directory (for workspace population)
    bool clone_into(const std::string& integrity_hash, const std::string& dest_dir) const;

    // Remove a stale entry
    void evict(const std::string& integrity_hash);

    // Stats
    size_t entry_count() const;
    uint64_t total_size_bytes() const;

private:
    std::string store_root_;  // ~/.aarchgate/cars/
    mutable std::mutex mutex_;
    std::unordered_map<std::string, CARSEntry> index_; // in-memory index

    void load_index();   // scan store_root_ on startup
    void save_index() const;
    static std::string hash_to_slot_name(const std::string& hash);
    static std::string aarchgate_dir();
};

} // namespace aarchgate
