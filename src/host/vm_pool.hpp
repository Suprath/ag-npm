// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Parallel VM Pool — Multi-VM Dependency Graph Installer (T3b)

#pragma once
#include "host/dep_graph.hpp"
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <atomic>
#include <string>

// Forward declaration to bypass undefined headers in prompt
namespace aarchgate {
class VMController {
public:
    VMController(const std::string&, const std::string&, const std::string&, const std::string&) {}
    bool start() { return true; }
    void stop() {}
};
}

namespace aarchgate {

struct VMJobResult {
    size_t subgraph_index;
    bool success;
    std::string error_message;
    std::vector<std::string> installed_packages; // "name@version"
    std::vector<std::string> blocked_packages;   // packages that failed policy
};

class VMPool {
public:
    VMPool(const std::string& kernel_path,
           const std::string& initrd_path,
           const std::string& share_path,
           size_t max_vms = 0);

    // Install all subgraphs in parallel, one VM per subgraph.
    // Calls result_cb for each completed subgraph (may be called from multiple threads).
    // Blocks until all VMs complete or any VM triggers a kill-switch.
    bool install_parallel(const std::vector<Subgraph>& subgraphs,
                          std::function<void(const VMJobResult&)> result_cb);

    size_t max_vms() const { return max_vms_; }

private:
    std::string kernel_path_;
    std::string initrd_path_;
    std::string share_path_;
    size_t max_vms_;
    std::atomic<bool> kill_switch_{false};
};

} // namespace aarchgate
