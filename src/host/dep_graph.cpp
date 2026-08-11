// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Package Dependency Graph — Lockfile Parser & Parallel Subgraph Extractor (T3a)

#include "dep_graph.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <thread>
#include <cmath>

namespace aarchgate {

static std::string trim_quotes(const std::string& str) {
    size_t start = str.find_first_not_of(" \"\t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \"\t\r\n,");
    return str.substr(start, end - start + 1);
}

bool DependencyGraph::parse(const std::string& lockfile_path) {
    std::ifstream file(lockfile_path);
    if (!file.is_open()) return false;

    std::string line;
    std::string current_pkg;
    DepNode current_node;
    bool in_packages = false;
    bool in_deps = false;

    // A very simple state machine parser for package-lock.json v2/v3
    while (std::getline(file, line)) {
        if (line.find("\"packages\": {") != std::string::npos) {
            in_packages = true;
            continue;
        }
        
        if (in_packages) {
            if (line.find("\"node_modules/") != std::string::npos) {
                if (!current_pkg.empty() && !current_node.version.empty()) {
                    std::string key = current_pkg + "@" + current_node.version;
                    nodes_[key] = current_node;
                }
                
                size_t start = line.find("\"node_modules/");
                size_t end = line.find("\"", start + 14);
                if (start != std::string::npos && end != std::string::npos) {
                    current_pkg = line.substr(start + 14, end - start - 14);
                    current_node = DepNode{};
                    current_node.name = current_pkg;
                }
            } else if (line.find("\"version\":") != std::string::npos) {
                size_t colon = line.find(":");
                current_node.version = trim_quotes(line.substr(colon + 1));
            } else if (line.find("\"resolved\":") != std::string::npos) {
                size_t colon = line.find(":");
                current_node.resolved_url = trim_quotes(line.substr(colon + 1));
            } else if (line.find("\"integrity\":") != std::string::npos) {
                size_t colon = line.find(":");
                current_node.integrity_hash = trim_quotes(line.substr(colon + 1));
            } else if (line.find("\"dependencies\": {") != std::string::npos) {
                in_deps = true;
            } else if (in_deps) {
                if (line.find("}") != std::string::npos) {
                    in_deps = false;
                } else {
                    size_t colon = line.find(":");
                    if (colon != std::string::npos) {
                        std::string dep_name = trim_quotes(line.substr(0, colon));
                        if (!dep_name.empty()) {
                            current_node.deps.push_back(dep_name);
                        }
                    }
                }
            }
        }
    }
    
    // add last node
    if (!current_pkg.empty() && !current_node.version.empty()) {
        std::string key = current_pkg + "@" + current_node.version;
        nodes_[key] = current_node;
    }

    // determine leaf nodes
    for (auto& [key, node] : nodes_) {
        node.is_leaf = node.deps.empty();
    }

    return true;
}

void DependencyGraph::topo_visit(const std::string& key,
                                 std::unordered_set<std::string>& visited,
                                 std::unordered_set<std::string>& in_stack,
                                 std::vector<std::string>& order) const {
    if (visited.count(key) || in_stack.count(key)) return;
    
    in_stack.insert(key);
    
    auto it = nodes_.find(key);
    if (it != nodes_.end()) {
        for (const auto& dep : it->second.deps) {
            // we only have names in deps, try to find a matching node
            for (const auto& [node_key, node] : nodes_) {
                if (node.name == dep) {
                    topo_visit(node_key, visited, in_stack, order);
                    break;
                }
            }
        }
    }
    
    in_stack.erase(key);
    visited.insert(key);
    order.push_back(key);
}

std::vector<DepNode> DependencyGraph::topological_order() const {
    std::unordered_set<std::string> visited;
    std::unordered_set<std::string> in_stack;
    std::vector<std::string> order_keys;

    for (const auto& [key, node] : nodes_) {
        if (!visited.count(key)) {
            topo_visit(key, visited, in_stack, order_keys);
        }
    }

    std::vector<DepNode> result;
    for (const auto& key : order_keys) {
        result.push_back(nodes_.at(key));
    }
    return result;
}

std::vector<Subgraph> DependencyGraph::extract_parallel_subgraphs(size_t max_vms) const {
    if (max_vms == 0) {
        max_vms = std::max<size_t>(1, std::thread::hardware_concurrency() / 2);
    }

    auto topo_nodes = topological_order();
    std::vector<Subgraph> subgraphs;
    
    // Greedy assignment: basic splitting logic
    size_t nodes_per_vm = (topo_nodes.size() + max_vms - 1) / max_vms;
    
    Subgraph current;
    for (const auto& node : topo_nodes) {
        current.push_back(node);
        if (current.size() >= nodes_per_vm) {
            subgraphs.push_back(current);
            current.clear();
        }
    }
    if (!current.empty()) {
        subgraphs.push_back(current);
    }
    
    // ensure we don't exceed max_vms due to rounding
    while (subgraphs.size() > max_vms) {
        auto last = subgraphs.back();
        subgraphs.pop_back();
        subgraphs.back().insert(subgraphs.back().end(), last.begin(), last.end());
    }

    return subgraphs;
}

} // namespace aarchgate
