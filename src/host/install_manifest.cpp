// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Incremental Differential Install Manifest (T8)

#include "install_manifest.hpp"
#include "integrity_verifier.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

namespace aarchgate {

static bool create_dir_recursively(const std::string& dir) {
    if (access(dir.c_str(), F_OK) == 0) return true;
    size_t pos = 0;
    while ((pos = dir.find_first_of('/', pos + 1)) != std::string::npos) {
        std::string parent = dir.substr(0, pos);
        mkdir(parent.c_str(), 0755);
    }
    return mkdir(dir.c_str(), 0755) == 0 || errno == EEXIST;
}

std::string InstallManifest::project_hash(const std::string& project_dir) {
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(project_dir.data(), project_dir.size(), hash);
    
    char hex[CC_SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        snprintf(&hex[i * 2], 3, "%02x", hash[i]);
    }
    return std::string(hex);
}

std::string InstallManifest::aarchgate_dir() {
    const char* home = getenv("HOME");
    if (home) {
        return std::string(home) + "/.aarchgate";
    }
    return "/tmp/.aarchgate";
}

InstallManifest::InstallManifest(const std::string& project_dir) : project_dir_(project_dir) {
    std::string hash = project_hash(project_dir);
    std::string dir = aarchgate_dir() + "/workspace/" + hash;
    create_dir_recursively(dir);
    manifest_path_ = dir + "/manifest.lock";
}

bool InstallManifest::load() {
    std::ifstream file(manifest_path_);
    if (!file.is_open()) return false;

    std::string line;
    entries_.clear();
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        
        std::istringstream ss(line);
        std::string nv, integrity, slot, ts;
        if (std::getline(ss, nv, '|') &&
            std::getline(ss, integrity, '|') &&
            std::getline(ss, slot, '|') &&
            std::getline(ss, ts)) {
            
            size_t at_pos = nv.rfind('@');
            if (at_pos != std::string::npos && at_pos > 0) {
                ManifestEntry entry;
                entry.name = nv.substr(0, at_pos);
                entry.version = nv.substr(at_pos + 1);
                entry.integrity_hash = integrity;
                entry.cars_slot = slot;
                try {
                    entry.install_time_ns = std::stoull(ts);
                } catch (...) {
                    entry.install_time_ns = 0;
                }
                entries_[nv] = entry;
            }
        }
    }
    return true;
}

bool InstallManifest::save() const {
    std::string dir = manifest_path_.substr(0, manifest_path_.rfind('/'));
    create_dir_recursively(dir);
    
    std::ofstream file(manifest_path_);
    if (!file.is_open()) return false;

    for (const auto& kv : entries_) {
        const auto& e = kv.second;
        file << e.name << "@" << e.version << "|"
             << e.integrity_hash << "|"
             << e.cars_slot << "|"
             << e.install_time_ns << "\n";
    }
    return true;
}

InstallDelta InstallManifest::diff(const std::string& new_lockfile_path) const {
    InstallDelta delta;
    auto new_packages = IntegrityVerifier::parse_lockfile(new_lockfile_path);
    std::unordered_map<std::string, bool> processed;

    for (const auto& pkg : new_packages) {
        std::string key = pkg.name + "@" + pkg.version;
        processed[key] = true;
        
        auto it = entries_.find(key);
        ManifestEntry entry;
        entry.name = pkg.name;
        entry.version = pkg.version;
        entry.integrity_hash = pkg.integrity_hash;

        if (it == entries_.end()) {
            delta.added.push_back(entry);
        } else {
            if (it->second.integrity_hash == pkg.integrity_hash) {
                entry.cars_slot = it->second.cars_slot;
                entry.install_time_ns = it->second.install_time_ns;
                delta.unchanged.push_back(entry);
            } else {
                delta.changed.push_back(entry);
            }
        }
    }

    for (const auto& kv : entries_) {
        if (processed.find(kv.first) == processed.end()) {
            delta.removed.push_back(kv.second);
        }
    }

    return delta;
}

void InstallManifest::update_entry(const ManifestEntry& entry) {
    std::string key = entry.name + "@" + entry.version;
    entries_[key] = entry;
}

void InstallManifest::remove_entry(const std::string& name) {
    // This is simple remove by name, a more complete impl might need name@version
    for (auto it = entries_.begin(); it != entries_.end(); ) {
        if (it->second.name == name) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace aarchgate
