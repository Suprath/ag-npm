// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Native POSIX Shared Memory Monitor IPC Protocol (Zero External Dependencies)

#pragma once

#include <cstdint>
#include <cstring>
#include <atomic>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef EVENT_EXEC
#define EVENT_EXEC 1
#define EVENT_OPEN 2
#define EVENT_CONNECT 3
#define EVENT_FORK 4
#endif

#define EVENT_MTE_TRAP 5
#define EVENT_VM_STATE_CHANGE 6

#define AARCHGATE_SHM_NAME "/aarchgate_telemetry_shm"
#define AARCHGATE_RING_CAPACITY 256

namespace aarchgate {

struct alignas(64) MonitorEvent {
    uint64_t timestamp_ns;
    uint64_t pid;
    uint64_t ppid;
    uint64_t event_type; // 1=EXEC, 2=OPEN, 3=CONNECT, 4=FORK, 5=MTE_TRAP, 6=VM_STATE_CHANGE
    char comm[32];
    char arg_str[256];
    uint32_t ip_address;
    uint16_t port;
    
    // Sandbox specific classifications
    uint8_t is_preinstall;
    uint8_t is_sensitive;
    uint8_t is_unauthorized;
    uint8_t vm_running; // 1 if VM is running, 0 if stopped/killed
    uint8_t padding[4];
};

struct MonitorSharedBuffer {
    std::atomic<uint64_t> write_index{0};
    std::atomic<uint64_t> read_index{0};
    MonitorEvent ring[AARCHGATE_RING_CAPACITY];
};

class SharedMemoryPublisher {
public:
    SharedMemoryPublisher() {
        int fd = shm_open(AARCHGATE_SHM_NAME, O_CREAT | O_RDWR, 0666);
        if (fd >= 0) {
            ftruncate(fd, sizeof(MonitorSharedBuffer));
            buffer_ = static_cast<MonitorSharedBuffer*>(mmap(nullptr, sizeof(MonitorSharedBuffer), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
            close(fd);
        }
    }

    void publish(const MonitorEvent& event) {
        if (!buffer_) return;
        uint64_t idx = buffer_->write_index.fetch_add(1, std::memory_order_acq_rel) % AARCHGATE_RING_CAPACITY;
        buffer_->ring[idx] = event;
    }

private:
    MonitorSharedBuffer* buffer_{nullptr};
};

class SharedMemorySubscriber {
public:
    SharedMemorySubscriber() {
        int fd = shm_open(AARCHGATE_SHM_NAME, O_RDWR, 0666);
        if (fd >= 0) {
            buffer_ = static_cast<MonitorSharedBuffer*>(mmap(nullptr, sizeof(MonitorSharedBuffer), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
            close(fd);
        }
    }

    bool pop(MonitorEvent& out_event) {
        if (!buffer_) {
            // Try connecting if newly created by daemon
            int fd = shm_open(AARCHGATE_SHM_NAME, O_RDWR, 0666);
            if (fd >= 0) {
                buffer_ = static_cast<MonitorSharedBuffer*>(mmap(nullptr, sizeof(MonitorSharedBuffer), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
                close(fd);
            }
        }
        if (!buffer_) return false;

        uint64_t w = buffer_->write_index.load(std::memory_order_acquire);
        uint64_t r = local_read_index_;

        if (r < w) {
            uint64_t idx = r % AARCHGATE_RING_CAPACITY;
            out_event = buffer_->ring[idx];
            local_read_index_++;
            return true;
        }

        return false;
    }

private:
    MonitorSharedBuffer* buffer_{nullptr};
    uint64_t local_read_index_{0};
};

} // namespace aarchgate
