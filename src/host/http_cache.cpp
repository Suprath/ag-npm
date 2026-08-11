#include "http_cache.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <sstream>
#include <iomanip>

namespace fs = std::filesystem;

namespace aarchgate {

std::string HTTPCache::aarchgate_dir() {
    const char* home = std::getenv("HOME");
    return home ? std::string(home) + "/.aarchgate" : "/tmp/.aarchgate";
}

HTTPCache::HTTPCache(const std::string& cache_dir, uint32_t default_ttl_seconds) 
    : default_ttl_s_(default_ttl_seconds) {
    cache_dir_ = cache_dir.empty() ? aarchgate_dir() + "/http_cache/" : cache_dir;
    if (cache_dir_.back() != '/') cache_dir_ += "/";
    fs::create_directories(cache_dir_);
}

std::string HTTPCache::url_to_filename(const std::string& url) {
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(url.c_str(), (CC_LONG)url.size(), hash);
    
    std::stringstream ss;
    for(int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str() + ".json";
}

bool HTTPCache::contains(const std::string& url) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(url);
    if (it == cache_.end()) return false;
    return std::chrono::system_clock::now() < it->second.expires_at;
}

CachedResponse HTTPCache::get(const std::string& url) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(url);
    if (it != cache_.end()) {
        if (std::chrono::system_clock::now() < it->second.expires_at) {
            return it->second;
        }
    }
    return CachedResponse{};
}

void HTTPCache::put(const std::string& url, const CachedResponse& response) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cache_[url] = response;
    }
    
    std::string filepath = cache_dir_ + url_to_filename(url);
    std::ofstream out(filepath);
    if (out) {
        auto duration = response.expires_at.time_since_epoch();
        uint64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
        out << "URL: " << response.url << "\n";
        out << "STATUS: " << response.status_code << "\n";
        out << "CONTENT-TYPE: " << response.content_type << "\n";
        out << "EXPIRES: " << timestamp << "\n";
        out << "---\n";
        out << response.body;
    }
}

void HTTPCache::put(const std::string& url, const std::string& body, const std::string& content_type, uint32_t ttl_seconds) {
    if (ttl_seconds == 0) ttl_seconds = default_ttl_s_;
    CachedResponse resp;
    resp.url = url;
    resp.body = body;
    resp.content_type = content_type;
    resp.status_code = 200;
    resp.expires_at = std::chrono::system_clock::now() + std::chrono::seconds(ttl_seconds);
    put(url, resp);
}

void HTTPCache::evict_expired() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::system_clock::now();
    for (auto it = cache_.begin(); it != cache_.end(); ) {
        if (now >= it->second.expires_at) {
            std::string filepath = cache_dir_ + url_to_filename(it->first);
            std::error_code ec;
            fs::remove(filepath, ec);
            it = cache_.erase(it);
        } else {
            ++it;
        }
    }
}

void HTTPCache::save_to_disk() const {
    // Current design saves to disk immediately on put()
}

bool HTTPCache::load_from_disk() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!fs::exists(cache_dir_)) return false;
    
    auto now = std::chrono::system_clock::now();
    for (const auto& entry : fs::directory_iterator(cache_dir_)) {
        if (entry.is_regular_file() && entry.path().extension() == ".json") {
            std::ifstream in(entry.path());
            if (!in) continue;
            
            CachedResponse resp;
            std::string line;
            uint64_t timestamp = 0;
            
            while (std::getline(in, line) && line != "---") {
                if (line.rfind("URL: ", 0) == 0) resp.url = line.substr(5);
                else if (line.rfind("STATUS: ", 0) == 0) resp.status_code = std::stoi(line.substr(8));
                else if (line.rfind("CONTENT-TYPE: ", 0) == 0) resp.content_type = line.substr(14);
                else if (line.rfind("EXPIRES: ", 0) == 0) timestamp = std::stoull(line.substr(9));
            }
            
            std::stringstream body_ss;
            body_ss << in.rdbuf();
            resp.body = body_ss.str();
            
            resp.expires_at = std::chrono::system_clock::time_point(std::chrono::seconds(timestamp));
            
            if (now < resp.expires_at) {
                cache_[resp.url] = resp;
            } else {
                std::error_code ec;
                fs::remove(entry.path(), ec);
            }
        }
    }
    return true;
}

size_t HTTPCache::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cache_.size();
}

} // namespace aarchgate
