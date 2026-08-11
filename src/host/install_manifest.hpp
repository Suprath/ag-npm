// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Incremental Differential Install Manifest (T8)

#pragma once
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>

namespace aarchgate {

struct ManifestEntry {
    std::string name;
    std::string version;
    std::string integrity_hash; // sha512-base64
    std::string cars_slot;     // CARS memory slot key
    uint64_t install_time_ns{0};
};

struct InstallDelta {
    std::vector<ManifestEntry> added;    // new packages not in old manifest
    std::vector<ManifestEntry> removed;  // packages removed from new lockfile
    std::vector<ManifestEntry> changed;  // packages with hash change (upgrade)
    std::vector<ManifestEntry> unchanged;// packages identical to manifest

    bool is_fully_cached() const { return added.empty() && changed.empty(); }
};

class InstallManifest {
public:
    explicit InstallManifest(const std::string& project_dir);

    // Load saved manifest from ~/.aarchgate/workspace/<project-hash>/manifest.lock
    bool load();

    // Save current manifest after successful install
    bool save() const;

    // Diff a new package-lock.json against saved manifest
    InstallDelta diff(const std::string& new_lockfile_path) const;

    // Update an entry after a successful cold-path install
    void update_entry(const ManifestEntry& entry);

    // Remove an entry
    void remove_entry(const std::string& name);

    size_t size() const { return entries_.size(); }
    const std::unordered_map<std::string, ManifestEntry>& entries() const { return entries_; }

private:
    std::string project_dir_;
    std::string manifest_path_;
    std::unordered_map<std::string, ManifestEntry> entries_; // keyed by "name@version"

    static std::string project_hash(const std::string& project_dir);
    static std::string aarchgate_dir();
};

} // namespace aarchgate
