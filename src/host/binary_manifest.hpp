// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Binary Packed Manifest Storage (32-Byte Packed Structs)
// Replaces line-by-line text lockfiles with mmap zero-copy binary serialization.

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace aarchgate {

#pragma pack(push, 1)
struct PackedManifestHeader {
    uint32_t magic;          // 0x41474D46 ("AGMF")
    uint32_t version;        // 1
    uint32_t entry_count;    // Total entries stored
    uint32_t flags;          // Reserved
    uint64_t timestamp_ns;   // Serialization timestamp
};

struct PackedManifestEntry {
    uint64_t hash_prefix;      // 8 bytes
    uint32_t package_id_hash;  // 4 bytes
    uint32_t cars_slot_index;  // 4 bytes
    uint64_t install_time_ns;  // 8 bytes
    uint16_t flags;            // 2 bytes
    uint16_t reserved;         // 2 bytes
    uint32_t reserved2;        // 4 bytes padding (total: 32 bytes)
};
#pragma pack(pop)

static_assert(sizeof(PackedManifestHeader) == 24, "Header must be 24 bytes");
static_assert(sizeof(PackedManifestEntry) == 32, "Entry must be 32 bytes aligned");

struct BinaryInstallDelta {
    std::vector<PackedManifestEntry> added;
    std::vector<PackedManifestEntry> removed;
    std::vector<PackedManifestEntry> changed;
    std::vector<PackedManifestEntry> unchanged;

    bool is_fully_cached() const { return added.empty() && changed.empty(); }
};

class BinaryManifest {
public:
    explicit BinaryManifest(const std::string& project_dir);

    // Load binary manifest via mmap (< 5µs)
    bool load();

    // Save binary manifest via sequential buffer write
    bool save() const;

    // Fast diff against lockfile
    BinaryInstallDelta diff(const std::string& lockfile_path) const;

    void update_entry(const PackedManifestEntry& entry);
    void remove_entry(uint32_t package_id_hash);

    size_t size() const { return entries_.size(); }
    const std::unordered_map<uint32_t, PackedManifestEntry>& entries() const { return entries_; }

    static uint32_t compute_package_id_hash(const std::string& name_version);
    static uint64_t compute_hash_prefix(const std::string& integrity_hash);

private:
    std::string project_dir_;
    std::string binary_path_;
    std::unordered_map<uint32_t, PackedManifestEntry> entries_; // keyed by package_id_hash

    static std::string project_hash(const std::string& project_dir);
    static std::string aarchgate_dir();
};

} // namespace aarchgate
