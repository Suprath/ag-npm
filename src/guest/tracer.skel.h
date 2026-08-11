// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Pre-Compiled eBPF Tracing Skeleton Header for Guest Linux Kernel

#ifndef __TRACER_SKEL_H__
#define __TRACER_SKEL_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// eBPF Event Types
#define EVENT_EXEC 1
#define EVENT_OPEN 2
#define EVENT_CONNECT 3
#define EVENT_FORK 4

struct syscall_event_t {
    uint64_t timestamp_ns;
    uint64_t pid;
    uint64_t ppid;
    uint64_t event_type;
    char comm[32];
    char arg_str[256];
    uint32_t ip_address;
    uint16_t port;
    uint8_t padding[2];
};

#ifdef __cplusplus
}
#endif

#endif // __TRACER_SKEL_H__
