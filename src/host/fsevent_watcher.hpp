// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: FSEvents Package.json Watcher — Preemptive Background Installation (T4)

#pragma once
#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <unordered_set>

namespace aarchgate {

class FSEventWatcher {
public:
    using ChangeCallback = std::function<void(const std::string& project_dir)>;

    FSEventWatcher();
    ~FSEventWatcher();

    // Start watching a project directory for package.json changes
    void watch(const std::string& project_dir);

    // Stop watching a directory
    void unwatch(const std::string& project_dir);

    // Set callback to invoke when package.json changes detected
    void set_callback(ChangeCallback cb);

    // Start the FSEvent stream dispatch
    void start();
    void stop();

private:
    ChangeCallback callback_;
    std::mutex mutex_;
    std::unordered_set<std::string> watched_dirs_;
    void* stream_ref_{nullptr};  // FSEventStreamRef (opaque void*)
    void* dispatch_queue_{nullptr}; // dispatch_queue_t (opaque)

    static void fs_event_callback(void* stream,
                                  void* client_info,
                                  size_t num_events,
                                  void* event_paths,
                                  const uint32_t* event_flags,
                                  const uint64_t* event_ids);
    void rebuild_stream();
};

} // namespace aarchgate
