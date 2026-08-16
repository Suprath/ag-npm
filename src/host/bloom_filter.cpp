// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: L1-Cached 8 KB Bitwise Bloom Filter Implementation

#include "host/bloom_filter.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <cstring>

namespace aarchgate {

BloomFilter::BloomFilter() {
    clear();
}

void BloomFilter::clear() {
    std::memset(words_, 0, sizeof(words_));
}

void BloomFilter::insert(uint64_t h1, uint64_t h2, uint64_t h3) {
    size_t idx1 = h1 % NUM_BITS;
    size_t idx2 = h2 % NUM_BITS;
    size_t idx3 = h3 % NUM_BITS;

    words_[idx1 / 64] |= (1ULL << (idx1 % 64));
    words_[idx2 / 64] |= (1ULL << (idx2 % 64));
    words_[idx3 / 64] |= (1ULL << (idx3 % 64));
}

void BloomFilter::insert_key(const std::string& key) {
    uint64_t h1, h2, h3;
    compute_hashes(key, h1, h2, h3);
    insert(h1, h2, h3);
}

bool BloomFilter::may_contain(uint64_t h1, uint64_t h2, uint64_t h3) const {
    size_t idx1 = h1 % NUM_BITS;
    size_t idx2 = h2 % NUM_BITS;
    size_t idx3 = h3 % NUM_BITS;

    uint64_t b1 = words_[idx1 / 64] & (1ULL << (idx1 % 64));
    uint64_t b2 = words_[idx2 / 64] & (1ULL << (idx2 % 64));
    uint64_t b3 = words_[idx3 / 64] & (1ULL << (idx3 % 64));

    return (b1 != 0) && (b2 != 0) && (b3 != 0);
}

bool BloomFilter::may_contain_key(const std::string& key) const {
    uint64_t h1, h2, h3;
    compute_hashes(key, h1, h2, h3);
    return may_contain(h1, h2, h3);
}

size_t BloomFilter::count_bits_set() const {
    size_t count = 0;
    for (size_t i = 0; i < NUM_WORDS; ++i) {
        count += __builtin_popcountll(words_[i]);
    }
    return count;
}

void BloomFilter::compute_hashes(const std::string& key, uint64_t& h1, uint64_t& h2, uint64_t& h3) {
    uint64_t hash = 14695981039346656037ULL;
    for (char c : key) {
        hash ^= static_cast<uint64_t>(c);
        hash *= 1099511628211ULL;
    }
    h1 = hash;
    h2 = (hash >> 17) | (hash << 47);
    h3 = (hash >> 31) | (hash << 33);
}

} // namespace aarchgate
