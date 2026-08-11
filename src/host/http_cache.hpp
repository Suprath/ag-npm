// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: HTTP Registry Response Cache + Request Coalescer (T7)

#pragma once
#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <cstdint>

namespace aarchgate {

struct CachedResponse {
    std::string url;
    std::string body;          // response body (JSON metadata)
    std::string content_type;
    uint32_t status_code{200};
    std::chrono::system_clock::time_point expires_at;
};

class HTTPCache {
public:
    explicit HTTPCache(const std::string& cache_dir = "",
                       uint32_t default_ttl_seconds = 300);

    // Check if a URL is in the cache and not expired
    bool contains(const std::string& url) const;

    // Get a cached response (returns empty CachedResponse if not found)
    CachedResponse get(const std::string& url) const;

    // Store a response in the cache
    void put(const std::string& url, const CachedResponse& response);
    void put(const std::string& url, const std::string& body,
             const std::string& content_type = "application/json",
             uint32_t ttl_seconds = 0);

    // Evict expired entries
    void evict_expired();

    // Persist cache index to disk
    void save_to_disk() const;

    // Load cache index from disk
    bool load_from_disk();

    size_t size() const;

private:
    std::string cache_dir_;    // ~/.aarchgate/http_cache/
    uint32_t default_ttl_s_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, CachedResponse> cache_;

    static std::string url_to_filename(const std::string& url);
    static std::string aarchgate_dir();
};

} // namespace aarchgate
