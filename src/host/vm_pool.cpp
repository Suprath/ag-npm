// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Parallel VM Pool — Multi-VM Dependency Graph Installer (T3b)

#include "vm_pool.hpp"
#include <iostream>
#include <algorithm>

namespace aarchgate {

VMPool::VMPool(const std::string& kernel_path,
               const std::string& initrd_path,
               const std::string& share_path,
               size_t max_vms)
    : kernel_path_(kernel_path),
      initrd_path_(initrd_path),
      share_path_(share_path),
      max_vms_(max_vms) {
    if (max_vms_ == 0) {
        max_vms_ = std::max<size_t>(1, std::thread::hardware_concurrency() / 2);
    }
}

bool VMPool::install_parallel(const std::vector<Subgraph>& subgraphs,
                              std::function<void(const VMJobResult&)> result_cb) {
    kill_switch_ = false;
    std::vector<std::thread> workers;
    
    std::mutex mtx;
    std::condition_variable cv;
    size_t active_vms = 0;
    
    for (size_t i = 0; i < subgraphs.size(); ++i) {
        if (kill_switch_) break;

        {
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait(lock, [&] { return active_vms < max_vms_; });
            active_vms++;
        }

        workers.emplace_back([this, i, subgraph = subgraphs[i], &result_cb, &mtx, &cv, &active_vms]() {
            if (kill_switch_) {
                std::unique_lock<std::mutex> lock(mtx);
                active_vms--;
                cv.notify_one();
                return;
            }

            // Simulate VM execution
            std::string vm_workspace = share_path_ + "/vm_" + std::to_string(i);
            VMController vm(kernel_path_, initrd_path_, share_path_, vm_workspace);
            
            bool success = vm.start();
            
            VMJobResult result;
            result.subgraph_index = i;
            result.success = success;
            if (success) {
                for (const auto& pkg : subgraph) {
                    result.installed_packages.push_back(pkg.name + "@" + pkg.version);
                }
            } else {
                result.error_message = "VM boot failed";
                kill_switch_ = true;
            }
            
            vm.stop();
            
            result_cb(result);

            {
                std::unique_lock<std::mutex> lock(mtx);
                active_vms--;
                cv.notify_one();
            }
        });
    }

    for (auto& t : workers) {
        if (t.joinable()) t.join();
    }

    return !kill_switch_;
}

} // namespace aarchgate
