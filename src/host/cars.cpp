#include "cars.hpp"
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <sys/stat.h>
#ifdef __APPLE__
#include <copyfile.h>
#endif

namespace fs = std::filesystem;

namespace aarchgate {

std::string ContentAddressableStore::aarchgate_dir() {
    const char* home = std::getenv("HOME");
    return home ? std::string(home) + "/.aarchgate" : "/tmp/.aarchgate";
}

ContentAddressableStore::ContentAddressableStore(const std::string& store_root) {
    store_root_ = store_root.empty() ? aarchgate_dir() + "/cars/" : store_root;
    if (store_root_.back() != '/') store_root_ += "/";
    fs::create_directories(store_root_);
    load_index();
}

void ContentAddressableStore::load_index() {
    std::lock_guard<std::mutex> lock(mutex_);
    bloom_filter_.clear();
    if (!fs::exists(store_root_)) return;
    for (const auto& entry : fs::directory_iterator(store_root_)) {
        if (entry.is_directory()) {
            std::string hash = entry.path().filename().string();
            CARSEntry cars_entry;
            cars_entry.integrity_hash = hash;
            cars_entry.slot_path = entry.path().string();
            
            uint64_t size = 0;
            for (const auto& f : fs::recursive_directory_iterator(entry.path())) {
                if (f.is_regular_file()) {
                    size += fs::file_size(f);
                }
            }
            cars_entry.size_bytes = size;
            
            struct stat st;
            if (stat(entry.path().c_str(), &st) == 0) {
#ifdef __APPLE__
                cars_entry.install_time_ns = st.st_mtimespec.tv_sec * 1000000000ULL + st.st_mtimespec.tv_nsec;
#else
                cars_entry.install_time_ns = st.st_mtim.tv_sec * 1000000000ULL + st.st_mtim.tv_nsec;
#endif
            }
            index_[hash] = cars_entry;
            bloom_filter_.insert_key(hash);
        }
    }
}

void ContentAddressableStore::save_index() const {
    // Current design does not persist index to a separate file, relies on load_index() scanning.
}

std::string ContentAddressableStore::hash_to_slot_name(const std::string& hash) {
    std::string safe_hash = hash;
    for (char& c : safe_hash) {
        if (c == '/' || c == '+' || c == '=') c = '_';
    }
    return safe_hash;
}

bool ContentAddressableStore::contains(const std::string& integrity_hash) const {
    // Sub-2ns Bloom filter check before acquiring mutex
    if (!bloom_filter_.may_contain_key(integrity_hash)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return index_.find(integrity_hash) != index_.end();
}

std::string ContentAddressableStore::get_slot_path(const std::string& integrity_hash) const {
    // Sub-2ns Bloom filter check before acquiring mutex
    if (!bloom_filter_.may_contain_key(integrity_hash)) {
        return "";
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = index_.find(integrity_hash);
    if (it != index_.end()) {
        return it->second.slot_path;
    }
    return "";
}


std::string ContentAddressableStore::put(const std::string& integrity_hash, const std::string& source_dir) {
    std::string slot_name = hash_to_slot_name(integrity_hash);
    std::string slot_path = store_root_ + slot_name;
    
    fs::create_directories(slot_path);
    fs::copy(source_dir, slot_path, fs::copy_options::recursive | fs::copy_options::overwrite_existing);
    
    uint64_t size = 0;
    for (const auto& f : fs::recursive_directory_iterator(slot_path)) {
        if (f.is_regular_file()) size += fs::file_size(f);
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    CARSEntry entry;
    entry.integrity_hash = integrity_hash;
    entry.slot_path = slot_path;
    entry.size_bytes = size;
    index_[integrity_hash] = entry;
    bloom_filter_.insert_key(integrity_hash);
    
    return slot_path;
}

bool ContentAddressableStore::clone_into(const std::string& integrity_hash, const std::string& dest_dir) const {
    std::string slot_path;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = index_.find(integrity_hash);
        if (it == index_.end()) return false;
        slot_path = it->second.slot_path;
    }

    std::error_code ec;

#ifdef __APPLE__
    // High-performance APFS Copy-on-Write kernel reflink clone (sub-millisecond latency)
    // Remove existing target if present, so copyfile creates dest_dir as identical clone root
    if (fs::exists(dest_dir)) {
        fs::remove_all(dest_dir, ec);
    }
    fs::create_directories(fs::path(dest_dir).parent_path(), ec);

    int res = copyfile(slot_path.c_str(), dest_dir.c_str(), nullptr, COPYFILE_CLONE | COPYFILE_RECURSIVE);
    if (res == 0) return true;
#endif

    // Fallback: standard filesystem recursive copy (non-APFS or cross-device mounts)
    fs::create_directories(dest_dir, ec);
    fs::copy(slot_path, dest_dir, fs::copy_options::recursive | fs::copy_options::overwrite_existing, ec);
    return !ec;
}

void ContentAddressableStore::evict(const std::string& integrity_hash) {
    std::string slot_path;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = index_.find(integrity_hash);
        if (it != index_.end()) {
            slot_path = it->second.slot_path;
            index_.erase(it);
        }
    }
    if (!slot_path.empty()) {
        std::error_code ec;
        fs::remove_all(slot_path, ec);
    }
}

size_t ContentAddressableStore::entry_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return index_.size();
}

uint64_t ContentAddressableStore::total_size_bytes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t total = 0;
    for (const auto& kv : index_) total += kv.second.size_bytes;
    return total;
}

} // namespace aarchgate
