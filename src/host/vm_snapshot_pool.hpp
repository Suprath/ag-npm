// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Warm VM Snapshot Pool — Eliminates Cold Boot Overhead (T6)

#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <memory>
#include <atomic>
#include <functional>

namespace aarchgate {

// Opaque handle to a warmed VM instance
struct WarmVM {
    int vm_id;
    bool is_ready{false};
    std::string workspace_mount_point;
};

class VMSnapshotPool {
public:
    explicit VMSnapshotPool(const std::string& kernel_path,
                            const std::string& initrd_path,
                            size_t pool_size = 3);
    ~VMSnapshotPool();

    // Start pre-booting VMs in background. Call once on daemon startup.
    void start_warming();

    // Get a warm VM handle (blocks up to timeout_ms if pool is empty).
    // Returns nullptr if timeout exceeded.
    std::shared_ptr<WarmVM> get_warm_vm(uint32_t timeout_ms = 5000);

    // Release a VM back to the pool (or destroy if kill_switch triggered)
    void release_vm(std::shared_ptr<WarmVM> vm, bool reuse = false);

    size_t pool_size() const { return pool_size_; }
    size_t available_count() const;

private:
    std::string kernel_path_;
    std::string initrd_path_;
    size_t pool_size_;
    std::atomic<bool> shutdown_{false};

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<std::shared_ptr<WarmVM>> warm_vms_;
    std::thread replenish_thread_;
    std::atomic<int> next_vm_id_{1};

    void replenish_loop();
    std::shared_ptr<WarmVM> boot_one_vm();
};

} // namespace aarchgate
