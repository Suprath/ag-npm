// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: NEON/CommonCrypto Hardware-Accelerated SHA-512 Integrity Verifier (T5)

#include "integrity_verifier.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <dispatch/dispatch.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <regex>
#include <mutex>
#include <sys/stat.h>

namespace aarchgate {

// Standard base64 encoding chars
static const char* b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode(const uint8_t* buf, unsigned int bufLen) {
    std::string ret;
    int i = 0;
    int j = 0;
    uint8_t char_array_3[3];
    uint8_t char_array_4[4];

    while (bufLen--) {
        char_array_3[i++] = *(buf++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
                ret += b64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += b64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';
    }
    return ret;
}

std::string IntegrityVerifier::sha512_hex(const uint8_t* data, size_t len) {
    unsigned char hash[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512(data, len, hash);
    
    char hex[CC_SHA512_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < CC_SHA512_DIGEST_LENGTH; i++) {
        snprintf(&hex[i * 2], 3, "%02x", hash[i]);
    }
    return std::string(hex);
}

std::string IntegrityVerifier::sha512_base64(const uint8_t* data, size_t len) {
    unsigned char hash[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512(data, len, hash);
    return "sha512-" + base64_encode(hash, CC_SHA512_DIGEST_LENGTH);
}

std::string IntegrityVerifier::read_file(const std::string& path, size_t& out_size) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        out_size = 0;
        return "";
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::string buffer(size, '\0');
    if (file.read(&buffer[0], size)) {
        out_size = size;
        return buffer;
    }
    out_size = 0;
    return "";
}

IntegrityResult IntegrityVerifier::verify_one(const PackageIntegrity& pkg) const {
    IntegrityResult result;
    result.name = pkg.name;
    result.version = pkg.version;
    result.expected_hash = pkg.integrity_hash;
    
    size_t size = 0;
    std::string content = read_file(pkg.tarball_path, size);
    
    if (size == 0 && content.empty()) {
        result.valid = false;
        result.failure_reason = "Failed to read tarball: " + pkg.tarball_path;
        return result;
    }
    
    result.actual_hash = sha512_base64(reinterpret_cast<const uint8_t*>(content.data()), size);
    result.valid = (result.actual_hash == result.expected_hash);
    if (!result.valid) {
        result.failure_reason = "Hash mismatch";
    }
    
    return result;
}

bool IntegrityVerifier::verify_all(const std::vector<PackageIntegrity>& packages,
                                   std::vector<IntegrityResult>& failures) const {
    if (packages.empty()) return true;

    std::mutex failures_mutex;
    std::mutex* mutex_ptr = &failures_mutex;
    std::vector<IntegrityResult>* failures_ptr = &failures;

    dispatch_apply(packages.size(), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(size_t i) {
        IntegrityResult res = verify_one(packages[i]);
        if (!res.valid) {
            std::lock_guard<std::mutex> lock(*mutex_ptr);
            failures_ptr->push_back(res);
        }
    });

    return failures.empty();
}


std::vector<PackageIntegrity> IntegrityVerifier::parse_lockfile(const std::string& lockfile_path) {
    std::vector<PackageIntegrity> packages;
    std::ifstream file(lockfile_path);
    if (!file.is_open()) return packages;

    std::string line;
    std::string current_name;
    std::string current_version;
    
    // Very simple parsing for "name", "version", "integrity"
    while (std::getline(file, line)) {
        // Skip dependencies object
        if (line.find("\"dependencies\":") != std::string::npos) continue;
        
        auto extract_val = [](const std::string& l, const std::string& key) -> std::string {
            size_t pos = l.find("\"" + key + "\":");
            if (pos != std::string::npos) {
                size_t start = l.find("\"", pos + key.length() + 3);
                if (start != std::string::npos) {
                    size_t end = l.find("\"", start + 1);
                    if (end != std::string::npos) {
                        return l.substr(start + 1, end - start - 1);
                    }
                }
            }
            return "";
        };

        // Note: Real parsing requires context stack, but for this exercise we extract what we can
        // Usually lockfile v3 has "node_modules/name": { "version": "...", "resolved": "...", "integrity": "..." }
        size_t node_mod_pos = line.find("\"node_modules/");
        if (node_mod_pos != std::string::npos) {
            size_t start = line.find("\"", node_mod_pos + 14);
            if (start != std::string::npos) {
                current_name = line.substr(node_mod_pos + 14, start - (node_mod_pos + 14));
            }
        }
        
        std::string v = extract_val(line, "version");
        if (!v.empty()) current_version = v;
        
        std::string integrity = extract_val(line, "integrity");
        if (!integrity.empty() && !current_name.empty() && integrity.find("sha512-") == 0) {
            PackageIntegrity pkg;
            pkg.name = current_name;
            pkg.version = current_version;
            pkg.integrity_hash = integrity;
            pkg.tarball_path = "node_modules/" + current_name + "/.aarchgate_tarball.tgz"; // Dummy path for testing
            packages.push_back(pkg);
            current_name = "";
            current_version = "";
        }
    }
    
    return packages;
}

} // namespace aarchgate
