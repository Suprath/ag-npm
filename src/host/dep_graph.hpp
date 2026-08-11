// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Package Dependency Graph — Lockfile Parser & Parallel Subgraph Extractor (T3a)

#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>

namespace aarchgate {

struct DepNode {
    std::string name;
    std::string version;
    std::string integrity_hash;
    std::string resolved_url;   // registry tarball URL
    std::vector<std::string> deps; // names of direct dependencies
    bool is_leaf{false};           // true if no deps or all deps already resolved
};

// A subgraph is a set of package names that can be installed independently
// (no inter-subgraph dependencies) and can be given to one parallel VM.
using Subgraph = std::vector<DepNode>;

class DependencyGraph {
public:
    // Parse a package-lock.json v2/v3 at the given path.
    // Returns false on parse failure.
    bool parse(const std::string& lockfile_path);

    // Perform topological sort and extract independent subgraphs.
    // Each returned Subgraph can be installed by a separate VM in parallel.
    // Max parallelism is bounded by max_vms (default: half of logical CPUs).
    std::vector<Subgraph> extract_parallel_subgraphs(size_t max_vms = 0) const;

    // All packages in topological install order (for sequential fallback)
    std::vector<DepNode> topological_order() const;

    size_t package_count() const { return nodes_.size(); }

private:
    std::unordered_map<std::string, DepNode> nodes_; // keyed by "name@version"

    // DFS topological sort
    void topo_visit(const std::string& key,
                    std::unordered_set<std::string>& visited,
                    std::unordered_set<std::string>& in_stack,
                    std::vector<std::string>& order) const;
};

} // namespace aarchgate
