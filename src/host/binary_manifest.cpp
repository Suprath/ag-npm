// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Binary Packed Manifest Implementation

#include "host/binary_manifest.hpp"
#include "host/integrity_verifier.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>

namespace fs = std::filesystem;

namespace aarchgate {

std::string BinaryManifest::aarchgate_dir() {
    const char* home = std::getenv("HOME");
    return std::string(home ? home : "/tmp") + "/.aarchgate";
}

std::string BinaryManifest::project_hash(const std::string& project_dir) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(project_dir.data(), static_cast<CC_LONG>(project_dir.size()), digest);
    
    char hex[65];
    for (int i = 0; i < 32; ++i) {
        snprintf(hex + (i * 2), 3, "%02x", digest[i]);
    }
    return std::string(hex, 64);
}

BinaryManifest::BinaryManifest(const std::string& project_dir) : project_dir_(project_dir) {
    std::string dir = aarchgate_dir() + "/workspace/" + project_hash(project_dir);
    fs::create_directories(dir);
    binary_path_ = dir + "/manifest.agmb";
}

uint32_t BinaryManifest::compute_package_id_hash(const std::string& name_version) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(name_version.data(), static_cast<CC_LONG>(name_version.size()), digest);
    uint32_t val;
    std::memcpy(&val, digest, sizeof(uint32_t));
    return val;
}

uint64_t BinaryManifest::compute_hash_prefix(const std::string& integrity_hash) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(integrity_hash.data(), static_cast<CC_LONG>(integrity_hash.size()), digest);
    uint64_t val;
    std::memcpy(&val, digest, sizeof(uint64_t));
    return val;
}

bool BinaryManifest::load() {
    entries_.clear();
    int fd = open(binary_path_.c_str(), O_RDONLY);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < static_cast<off_t>(sizeof(PackedManifestHeader))) {
        close(fd);
        return false;
    }

    void* addr = mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (addr == MAP_FAILED) return false;

    auto* header = reinterpret_cast<const PackedManifestHeader*>(addr);
    if (header->magic != 0x41474D46) { // "AGMF"
        munmap(addr, st.st_size);
        return false;
    }

    const auto* entries_ptr = reinterpret_cast<const PackedManifestEntry*>(
        reinterpret_cast<const uint8_t*>(addr) + sizeof(PackedManifestHeader)
    );

    for (uint32_t i = 0; i < header->entry_count; ++i) {
        entries_[entries_ptr[i].package_id_hash] = entries_ptr[i];
    }

    munmap(addr, st.st_size);
    return true;
}

bool BinaryManifest::save() const {
    std::vector<PackedManifestEntry> entry_list;
    entry_list.reserve(entries_.size());
    for (const auto& [_, entry] : entries_) {
        entry_list.push_back(entry);
    }

    PackedManifestHeader header{};
    header.magic = 0x41474D46; // "AGMF"
    header.version = 1;
    header.entry_count = static_cast<uint32_t>(entry_list.size());
    header.flags = 0;
    header.timestamp_ns = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count()
    );

    std::ofstream file(binary_path_, std::ios::binary);
    if (!file.is_open()) return false;

    file.write(reinterpret_cast<const char*>(&header), sizeof(header));
    if (!entry_list.empty()) {
        file.write(reinterpret_cast<const char*>(entry_list.data()),
                   entry_list.size() * sizeof(PackedManifestEntry));
    }

    return file.good();
}

BinaryInstallDelta BinaryManifest::diff(const std::string& lockfile_path) const {
    BinaryInstallDelta delta;
    auto pkgs = IntegrityVerifier::parse_lockfile(lockfile_path);

    std::unordered_map<uint32_t, PackedManifestEntry> lock_map;
    for (const auto& p : pkgs) {
        std::string key = p.name + "@" + p.version;
        uint32_t id_hash = compute_package_id_hash(key);
        
        PackedManifestEntry entry{};
        entry.package_id_hash = id_hash;
        entry.hash_prefix = compute_hash_prefix(p.integrity_hash);
        entry.cars_slot_index = 0;
        entry.install_time_ns = 0;
        entry.flags = 0;

        lock_map[id_hash] = entry;
    }

    // Identify added or changed
    for (const auto& [id, entry] : lock_map) {
        auto it = entries_.find(id);
        if (it == entries_.end()) {
            delta.added.push_back(entry);
        } else if (it->second.hash_prefix != entry.hash_prefix) {
            delta.changed.push_back(entry);
        } else {
            delta.unchanged.push_back(it->second);
        }
    }

    // Identify removed
    for (const auto& [id, entry] : entries_) {
        if (lock_map.find(id) == lock_map.end()) {
            delta.removed.push_back(entry);
        }
    }

    return delta;
}

void BinaryManifest::update_entry(const PackedManifestEntry& entry) {
    entries_[entry.package_id_hash] = entry;
}

void BinaryManifest::remove_entry(uint32_t package_id_hash) {
    entries_.erase(package_id_hash);
}

} // namespace aarchgate
