// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: FSEvents Package.json Watcher — Preemptive Background Installation (T4)

#include "fsevent_watcher.hpp"
#include <CoreServices/CoreServices.h>
#include <Foundation/Foundation.h>
#include <iostream>

namespace aarchgate {

FSEventWatcher::FSEventWatcher() {}

FSEventWatcher::~FSEventWatcher() {
    stop();
}

void FSEventWatcher::watch(const std::string& project_dir) {
    std::lock_guard<std::mutex> lock(mutex_);
    watched_dirs_.insert(project_dir);
    if (dispatch_queue_) {
        rebuild_stream();
    }
}

void FSEventWatcher::unwatch(const std::string& project_dir) {
    std::lock_guard<std::mutex> lock(mutex_);
    watched_dirs_.erase(project_dir);
    if (dispatch_queue_) {
        rebuild_stream();
    }
}

void FSEventWatcher::set_callback(ChangeCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = cb;
}

void FSEventWatcher::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (dispatch_queue_) return;
    
    dispatch_queue_ = dispatch_queue_create("com.aarchgate.fsevent", nullptr);
    rebuild_stream();
}

void FSEventWatcher::stop() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (stream_ref_) {
        FSEventStreamStop((FSEventStreamRef)stream_ref_);
        FSEventStreamInvalidate((FSEventStreamRef)stream_ref_);
        FSEventStreamRelease((FSEventStreamRef)stream_ref_);
        stream_ref_ = nullptr;
    }
    if (dispatch_queue_) {
        dispatch_release((dispatch_queue_t)dispatch_queue_);
        dispatch_queue_ = nullptr;
    }
}

void FSEventWatcher::rebuild_stream() {
    if (stream_ref_) {
        FSEventStreamStop((FSEventStreamRef)stream_ref_);
        FSEventStreamInvalidate((FSEventStreamRef)stream_ref_);
        FSEventStreamRelease((FSEventStreamRef)stream_ref_);
        stream_ref_ = nullptr;
    }

    if (watched_dirs_.empty()) return;

    NSMutableArray *paths = [NSMutableArray arrayWithCapacity:watched_dirs_.size()];
    for (const auto& dir : watched_dirs_) {
        NSString *nsStr = [NSString stringWithUTF8String:dir.c_str()];
        [paths addObject:nsStr];
    }

    FSEventStreamContext context = {0, this, nullptr, nullptr, nullptr};
    NSTimeInterval latency = 0.5;

    stream_ref_ = FSEventStreamCreate(
        nullptr,
        (FSEventStreamCallback)&FSEventWatcher::fs_event_callback,
        &context,
        (__bridge CFArrayRef)paths,
        kFSEventStreamEventIdSinceNow,
        latency,
        kFSEventStreamCreateFlagUseCFTypes | kFSEventStreamCreateFlagFileEvents
    );

    if (stream_ref_ && dispatch_queue_) {
        FSEventStreamSetDispatchQueue((FSEventStreamRef)stream_ref_, (dispatch_queue_t)dispatch_queue_);
        FSEventStreamStart((FSEventStreamRef)stream_ref_);
    }
}

void FSEventWatcher::fs_event_callback(void* stream,
                                       void* client_info,
                                       size_t num_events,
                                       void* event_paths,
                                       const uint32_t* event_flags,
                                       const uint64_t* event_ids) {
    FSEventWatcher* watcher = static_cast<FSEventWatcher*>(client_info);
    NSArray *paths = (__bridge NSArray *)event_paths;

    for (size_t i = 0; i < num_events; i++) {
        NSString *path = [paths objectAtIndex:i];
        if ([path.lastPathComponent isEqualToString:@"package.json"]) {
            NSString *dir = [path stringByDeletingLastPathComponent];
            std::string cpp_dir = [dir UTF8String];
            
            std::lock_guard<std::mutex> lock(watcher->mutex_);
            if (watcher->callback_) {
                watcher->callback_(cpp_dir);
            }
        }
    }
}

} // namespace aarchgate
