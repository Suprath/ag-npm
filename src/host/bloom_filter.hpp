// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: L1-Cached 8 KB Bitwise Bloom Filter
// Provides sub-2ns cache miss rejections for CARS and HTTP Cache lookups.

#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <string>

namespace aarchgate {

class BloomFilter {
public:
    // 65,536 bits = 8,192 bytes (8 KB) — perfectly fits L1 Data Cache
    static constexpr size_t NUM_BITS = 65536;
    static constexpr size_t NUM_WORDS = NUM_BITS / 64; // 1024 uint64_t words

    BloomFilter();

    // Clear all bits in the Bloom filter
    void clear();

    // Insert a triple-hash signature into the Bloom filter
    void insert(uint64_t h1, uint64_t h2, uint64_t h3);

    // Insert a string by calculating 3 hash values using CommonCrypto SHA256/Murmur
    void insert_key(const std::string& key);

    // Test if a key MAY be in the set (false = 100% definitely NOT in set)
    bool may_contain(uint64_t h1, uint64_t h2, uint64_t h3) const;
    bool may_contain_key(const std::string& key) const;

    size_t count_bits_set() const;

private:
    uint64_t words_[NUM_WORDS];

    static void compute_hashes(const std::string& key, uint64_t& h1, uint64_t& h2, uint64_t& h3);
};

} // namespace aarchgate
