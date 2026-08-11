// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Warm VM Snapshot Pool — Eliminates Cold Boot Overhead (T6)

#include "vm_snapshot_pool.hpp"
#include <chrono>

namespace aarchgate {

VMSnapshotPool::VMSnapshotPool(const std::string& kernel_path,
                               const std::string& initrd_path,
                               size_t pool_size)
    : kernel_path_(kernel_path),
      initrd_path_(initrd_path),
      pool_size_(pool_size) {}

VMSnapshotPool::~VMSnapshotPool() {
    shutdown_ = true;
    cv_.notify_all();
    if (replenish_thread_.joinable()) {
        replenish_thread_.join();
    }
}

void VMSnapshotPool::start_warming() {
    replenish_thread_ = std::thread(&VMSnapshotPool::replenish_loop, this);
}

void VMSnapshotPool::replenish_loop() {
    while (!shutdown_) {
        bool needs_replenish = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            needs_replenish = (warm_vms_.size() < pool_size_);
        }

        if (needs_replenish) {
            auto new_vm = boot_one_vm();
            if (new_vm) {
                std::lock_guard<std::mutex> lock(mutex_);
                warm_vms_.push_back(new_vm);
                cv_.notify_one();
            }
        } else {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return warm_vms_.size() < pool_size_ || shutdown_; });
        }
    }
}

std::shared_ptr<WarmVM> VMSnapshotPool::boot_one_vm() {
    // Simulate boot time
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    
    if (shutdown_) return nullptr;

    auto vm = std::make_shared<WarmVM>();
    vm->vm_id = next_vm_id_++;
    vm->is_ready = true;
    vm->workspace_mount_point = "/tmp/aarchgate/warm_vm_" + std::to_string(vm->vm_id);
    return vm;
}

std::shared_ptr<WarmVM> VMSnapshotPool::get_warm_vm(uint32_t timeout_ms) {
    std::unique_lock<std::mutex> lock(mutex_);
    
    if (cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), 
                     [this] { return !warm_vms_.empty() || shutdown_; })) {
        if (!warm_vms_.empty()) {
            auto vm = warm_vms_.back();
            warm_vms_.pop_back();
            cv_.notify_one(); // wake up replenish_loop
            return vm;
        }
    }
    return nullptr;
}

void VMSnapshotPool::release_vm(std::shared_ptr<WarmVM> vm, bool reuse) {
    if (!vm) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    if (reuse) {
        warm_vms_.push_back(vm);
    }
    cv_.notify_one();
}

size_t VMSnapshotPool::available_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return warm_vms_.size();
}

} // namespace aarchgate
