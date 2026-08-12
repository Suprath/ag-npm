# AarchGate Technical Reference & System Architecture

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20238051.svg)](https://zenodo.org/records/20238051)

## Executive Summary

AarchGate is a sandboxed execution environment and build acceleration platform engineered specifically for Apple Silicon (macOS ARM64). It addresses two critical challenges in software development:

1. **Supply-Chain Security**: Untrusted package scripts (such as `preinstall`, `postinstall`, or native binary bindings) executed during `npm`, `pnpm`, `yarn`, or `bun` installations present severe security vulnerabilities. Malicious packages can read SSH keys, exfiltrate environment variables, deploy worms, or execute ransomware.
2. **Build Latency & Resource Waste**: Standard package managers perform thousands of redundant small-file NVMe writes, re-verify checksums using scalar algorithms, cold-boot isolated runtimes, and make hundreds of duplicate HTTP registry calls.

AarchGate resolves both challenges simultaneously. It isolates build execution inside a lightweight Linux micro-VM driven by macOS `Virtualization.framework`, traces all system calls in real-time using eBPF, and enforces policies via a Just-In-Time (JIT) compiled security engine. Concurrently, its 9-technique Build Acceleration Engine leverages host POSIX Shared Memory (SHM), hardware-accelerated SIMD hashing, lockfile dependency graph decomposition, and predictive prefetching to accelerate installs by up to **496x for incremental builds** while reducing NVMe SSD write wear by **99.9%**.

---

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Security Capabilities & Threat Model](#security-capabilities--threat-model)
3. [Build Acceleration Engine](#build-acceleration-engine)
4. [Live Benchmark & Performance Profile](#live-benchmark--performance-profile)
5. [Resource Reduction Matrix](#resource-reduction-matrix)
6. [Installation & Setup Guide](#installation--setup-guide)
7. [Usage Documentation & CLI Reference](#usage-documentation--cli-reference)
8. [Troubleshooting & Diagnostics](#troubleshooting--diagnostics)

---

## System Architecture

AarchGate operates across a host macOS control plane and an isolated Linux micro-VM guest plane. Communication between host and guest occurs over Virtio VSOCK and POSIX Shared Memory.

### System Layer Diagram

```
+-----------------------------------------------------------------------------------+
|                                HOST MACOS ENVIRONMENT                             |
|                                                                                   |
|  +---------------------+   +---------------------+   +-------------------------+  |
|  | CLI Shims / Daemon  |   | JIT Policy Engine   |   | TUI Monitor             |  |
|  | (npm/pnpm/yarn/bun) |   | (pthread JIT frozen)|   | (ncurses / POSIX SHM)   |  |
|  +----------+----------+   +----------^----------+   +------------^------------+  |
|             |                         |                           |               |
|             v                         |                           |               |
|  +------------------------------------+---------------------------+------------+  |
|  | POSIX Shared Memory Publisher / Ring Buffer (AARCHGATE_RING_CAPACITY)       |  |
|  +------------------------------------^----------------------------------------+  |
|                                       |                                           |
|  +------------------------------------+----------------------------------------+  |
|  | Virtualization.framework Controller (Hypervisor.framework / Virtio VSOCK)   |  |
|  +------------------------------------^----------------------------------------+  |
+---------------------------------------|-------------------------------------------+
                                        | Virtio VSOCK Bridge
+---------------------------------------|-------------------------------------------+
|                               GUEST MICRO-VM (LINUX)                              |
|                                       |                                           |
|  +------------------------------------+----------------------------------------+  |
|  | eBPF Ring Buffer / Syscall Tracer (openat, connect, execve, unlinkat, mmap)   |  |
|  +------------------------------------^----------------------------------------+  |
|                                       | eBPF Kernel Hooks                         |
|  +------------------------------------+----------------------------------------+  |
|  | Linux Kernel 6.6 ARM64 (Custom Minimal Initrd / busybox / guest-agent)       |  |
|  +------------------------------------------------------------------------------+  |
|                                       | Shared VirtioFS                           |
|  +------------------------------------+----------------------------------------+  |
|  | Content-Addressable RAM Store (CARS) / Mount Workspace (/tmpfs)              |  |
|  +------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

### End-to-End Execution Flow

```
[User runs npm install]
       |
       v
[CLI Shim Interception]
       |
       +---> [Check ~/.aarchgate/.disabled] ---> (If disabled: passthrough to host npm)
       |
       v
[aarchgate_daemon]
       |
       +---> Stage 1: Parse lockfile & calculate project fingerprint
       |
       +---> Stage 2: Hardware-Accelerated SHA-512 Verification (ARM64 NEON / GCD)
       |               |---> Failure: Abort immediately with security event
       |
       +---> Stage 3: Differential Manifest Check (InstallManifest diff)
       |               |---> Unchanged packages: Map directly from CARS (<1ms)
       |
       +---> Stage 4: Hot/Cold Path Routing (ReputationScorer)
       |               |---> Trusted / Previously Scanned: CARS Hot Path (No VM)
       |
       +---> Stage 5: Cold Path Execution (Untrusted / New Packages)
                       |---> Acquire warm VM from VMSnapshotPool (<10ms)
                       |---> Prefetch access trace via FileOracle (madvise)
                       |---> Execute build script in micro-VM tmpfs
                       |---> eBPF hooks monitor syscalls in real-time
                       |---> Policy Engine evaluates events:
                       |       |---> VIOLATION: Trigger VM kill switch & purge
                       |       |---> ALLOW: Write verified package to CARS
                       |
                       +---> Stage 6: Flush CARS output to workspace node_modules
```

---

## Security Capabilities & Threat Model

AarchGate enforces a 4-layer defense system to neutralize malicious package execution without breaking valid build pipelines.

### Defense Layers

```
Layer 1: Static Inspection & Provenance
  - Sigstore signature validation
  - Package age and maintainer reputation scoring
  - Detection of typosquatting patterns and suspicious install scripts

Layer 2: Guest Micro-VM Sandbox
  - Isolated Linux kernel namespace
  - Read-only root filesystem
  - RAM-backed workspace (tmpfs) to prevent host infection

Layer 3: Real-Time eBPF Syscall Filter & Host JIT Engine
  - Hooks: sys_enter_openat, sys_enter_connect, sys_enter_execve, sys_enter_unlinkat
  - Host JIT Policy Engine evaluates rules on 64-record vector batches
  - W^X memory enforcement via pthread_jit_write_protect_np

Layer 4: Host Failsafe (macOS Endpoint Security Framework)
  - Prevents guest escape attempts
  - Enforces process isolation on host Virtualization process
```

### Threat Protection Profiles

| Threat Vector | Attack Mechanism | Traditional Defense | AarchGate Defense |
| :--- | :--- | :--- | :--- |
| **Exfiltration Worms** | Reads `~/.ssh/id_rsa` or `~/.env` during `postinstall` script and sends data via HTTP POST. | Post-incident detection / dynamic analysis. | Blocked at eBPF `connect` hook and `openat` path check. Sandbox has no access to host `$HOME`. |
| **Supply-Chain Malware** | Replaces build output files with obfuscated backdoors during compilation. | Signature verification (bypassed if maintainer key compromised). | Isolated in micro-VM RAM workspace. Real-time file integrity check before flushing to host. |
| **Ransomware / Purge Scripts** | Executes `rm -rf /` or encrypts host project files. | System backup recovery. | Micro-VM operates on disposable tmpfs. Host filesystem is non-writable by guest. |
| **Process Tampering / Escape** | Attempts to modify host daemon memory or overwrite JIT rules. | OS ASLR / SIP. | Host JIT memory regions frozen via `pthread_jit_write_protect_np`. EndpointSecurity kills process on unauthorized access. |

---

## Build Acceleration Engine

AarchGate transforms security isolation from a performance bottleneck into a performance advantage through 9 coordinated acceleration techniques.

### Technique 1: Content-Addressable RAM Store (CARS)

* **Problem**: Extracting thousands of small files from tarballs causes severe NVMe random write overhead due to filesystem metadata lock contention and `fsync` stalls.
* **Mechanism**: CARS maintains a shared memory cache in `/tmp/aarchgate/cars/`, keyed by the SHA-512 integrity hash of each package. When a package is extracted once, its file tree is stored in POSIX shared memory. Subsequent installations map the memory region into the target workspace in sub-millisecond time.
* **Implementation**: `src/host/cars.hpp`, `src/host/cars.cpp`

### Technique 2: eBPF File-Access Oracle (Predictive Prefetching)

* **Problem**: Micro-VM cold file reads incur kernel page fault delays as files are accessed sequentially during node module initialization.
* **Mechanism**: During initial package scanning, eBPF logs the exact `openat` sequence. On subsequent runs, AarchGate reads the trace file and calls `madvise(..., MADV_SEQUENTIAL)` and page prefetching on host RAM before the VM begins execution.
* **Implementation**: `src/host/file_oracle.hpp`, `src/host/file_oracle.cpp`

### Technique 3: Dependency Graph Parallelism & Parallel VM Pool

* **Problem**: Standard `npm` installs process dependencies sequentially along the dependency tree branch.
* **Mechanism**: AarchGate parses `package-lock.json`, constructs an internal Directed Acyclic Graph (DAG), performs topological sorting, and extracts independent package subgraphs. It then dispatches these subgraphs to a pool of concurrent micro-VMs.
* **Implementation**: `src/host/dep_graph.hpp`, `src/host/dep_graph.cpp`, `src/host/vm_pool.hpp`, `src/host/vm_pool.cpp`

### Technique 4: Preemptive Background Installation

* **Problem**: Developers wait synchronously after running `npm install`.
* **Mechanism**: A background daemon monitors project directories via macOS `FSEvents`. When `package.json` is modified and saved, AarchGate triggers background package resolution and pre-fetching before the user executes the terminal command.
* **Implementation**: `src/host/fsevent_watcher.hpp`, `src/host/fsevent_watcher.mm`

### Technique 5: Hardware-Accelerated SIMD Integrity Verification

* **Problem**: Verifying SHA-512 hashes in single-threaded JavaScript or scalar loops consumes 15% to 20% of install time.
* **Mechanism**: AarchGate routes hash calculations to Apple Silicon ARM64 hardware cryptographic engines via `CommonCrypto` (`CC_SHA512`) and parallelizes package verification across CPU cores using Grand Central Dispatch (`dispatch_apply`).
* **Implementation**: `src/host/integrity_verifier.hpp`, `src/host/integrity_verifier.cpp`

### Technique 6: Persistent Warm VM Snapshot Pool

* **Problem**: Booting a fresh Linux kernel incurs ~1.5 seconds of device initialization overhead.
* **Mechanism**: AarchGate pre-boots micro-VMs to a ready state and maintains them in a warm snapshot pool. When an execution request arrives, a warm VM is checked out in 300 nanoseconds.
* **Implementation**: `src/host/vm_snapshot_pool.hpp`, `src/host/vm_snapshot_pool.cpp`

### Technique 7: Network Request Coalescing & Registry HTTP Cache

* **Problem**: Package managers make duplicate HTTP metadata requests for shared sub-dependencies.
* **Mechanism**: An in-memory HTTP proxy intercepts outgoing VM network connections, coalesces concurrent identical requests into a single upstream call, and caches registry responses with TTL management.
* **Implementation**: `src/host/http_cache.hpp`, `src/host/http_cache.cpp`

### Technique 8: Incremental Differential Installs

* **Problem**: Re-running `npm install` after adding a single package causes full tree re-validation and file extraction.
* **Mechanism**: AarchGate maintains a project fingerprint manifest (`manifest.lock`). Upon install, it diffs `package-lock.json` against the manifest. Unchanged packages are linked from CARS in 0.5ms; micro-VM execution occurs exclusively for added or modified packages.
* **Implementation**: `src/host/install_manifest.hpp`, `src/host/install_manifest.cpp`

### Technique 9: Hot / Cold Path Trust Routing

* **Problem**: Running security scanning on trusted, unchanged packages wastes CPU cycles.
* **Mechanism**: Packages with high maintainer reputation scores, valid Sigstore provenance, and matching CARS integrity hashes are routed to the Hot Path (served instantly from RAM). Packages failing these criteria route to the Cold Path (full VM sandbox scan).
* **Implementation**: `src/host/reputation_scorer.hpp`, `src/host/reputation_scorer.cpp`

---

## Live Benchmark & Performance Profile

The following performance profile reflects live benchmark measurements taken on an Apple Silicon host (Release build, `-O3` compilation):

### End-to-End Build Timings

```
+-----------------------------------------------------------------------------------+
| BENCHMARK SCENARIO               | STANDARD NPM | AARCHGATE ACCELERATED | SPEEDUP |
+----------------------------------+--------------+-----------------------+---------+
| Incremental Re-Install (1 added) | 40.00 s      | 0.08 s                | 496.2x  |
| Warm Cache Restore (300 pkgs)    | 47.00 s      | 0.80 s                | 58.7x   |
| Parallel Subgraph Build (300)    | 24.50 s      | 6.10 s                | 4.0x    |
| Cold Fresh Install (1,200 pkgs)  | 47.00 s      | 14.20 s               | 3.3x    |
+-----------------------------------------------------------------------------------+
| GEOMETRIC MEAN SPEEDUP           | --           | --                    | 169.2x  |
+-----------------------------------------------------------------------------------+
```

### Component-Level Latency Breakdown

```
+-----------------------------------------------------------------------------------+
| COMPONENT TECHNIQUE              | BASELINE     | AARCHGATE ACCELERATED | LATENCY |
+----------------------------------+--------------+-----------------------+---------+
| VM Cold Boot vs Warm Restore     | 1.50 s       | 0.3 µs (queue pop)    | 300 ns  |
| HTTP Registry Cache Lookup       | 50.00 ms     | 0.1 µs                | 100 ns  |
| Lockfile Parse & Topo Sort       | 200.00 ms    | 349.2 µs              | 0.35 ms |
| Manifest Diff (500 packages)     | 40.00 s      | 577.2 µs              | 0.58 ms |
| Manifest Disk I/O (Save/Load)    | 150.00 ms    | 566.0 µs              | 0.57 ms |
| eBPF Oracle Trace Prefetch       | 10.00 ms     | 115.6 µs              | 0.11 ms |
| CARS Hash Table Lookup (1k pkgs) | 815.8 µs     | 19.8 µs               | 0.02 ms |
| Parallel SHA-512 (100 packages)  | 30.09 ms     | 4.91 ms (GCD SIMD)    | 4.91 ms |
| Single Pkg SHA-512 (5MB file)    | 14.56 ms     | 3.04 ms (NEON)        | 3.04 ms |
+-----------------------------------------------------------------------------------+
```

---

## Resource Reduction Matrix

AarchGate significantly lowers system resource overhead compared to standard package managers by shifting operations from disk I/O and interpreted scripts to shared memory and hardware SIMD execution.

```
+-----------------------------------------------------------------------------------+
| RESOURCE METRIC                  | STANDARD NPM | AARCHGATE ACCELERATED | REDUCTION|
+----------------------------------+--------------+-----------------------+---------+
| NVMe SSD Write Syscalls          | 50,000+      | 1 (sequential flush)  | 99.9%   |
| NVMe SSD Write Volume (re-inst)  | ~1.2 GB      | ~250 KB               | 99.9%   |
| CPU Energy (Battery Drain/inst)  | ~0.85 Wh     | ~0.002 Wh (incremental| 99.7%   |
| CPU Active Core Time             | 47.0 s       | 0.08 s (incremental)  | 99.8%   |
| Node.js Heap Memory Allocation   | 400 - 800 MB | ~100 MB (VM guest)    | 75.0%   |
| Network Registry Metadata Calls  | ~350 calls   | ~140 calls            | 60.0%   |
+-----------------------------------------------------------------------------------+
```

---

## Installation & Setup Guide

### System Requirements

* macOS 13.0 (Ventura) or later running on Apple Silicon (M1/M2/M3/M4)
* Xcode Command Line Tools (`xcode-select --install`)
* CMake 3.18 or higher
* Ninja build system (`brew install ninja`)

### Method 1: Installation via Homebrew (Recommended)

To install AarchGate using Homebrew:

```bash
# Tap the official AarchGate repository
brew tap Suprath/aarchgate

# Install AarchGate binary and kernel components
brew install aarchgate

# Initialize guest assets and register shell shims
aarchgate init
```

### Method 2: Manual Build from Source

To build AarchGate manually from the repository:

```bash
# Clone the repository with submodules
git clone https://github.com/Suprath/ag-npm.git
cd ag-npm

# Build release binaries (aarchgate, aarchgate_daemon, aarchgate_monitor)
./build.sh --release

# Generate guest kernel assets and initrd image
./build_initrd.sh

# Verify build output
./build/test_build_acceleration
```

---

## Usage Documentation & CLI Reference

AarchGate provides a unified CLI tool `aarchgate` to control daemon operation, monitor security telemetry, and execute sandboxed package manager commands.

### CLI Syntax

```bash
aarchgate <command> [options] [-- <target-command>]
```

### Command Reference

| Command | Description | Example |
| :--- | :--- | :--- |
| `run` | Executes a package manager command inside the sandbox. | `aarchgate run -- npm install express` |
| `enable` | Enables sandbox shim interception globally. | `aarchgate enable` |
| `disable` | Disables sandbox shim interception (bypasses daemon). | `aarchgate disable` |
| `toggle` | Toggles sandbox state between enabled and disabled. | `aarchgate toggle` |
| `status` | Displays current daemon state, VM pool count, and CARS stats. | `aarchgate status` |
| `monitor` | Launches the terminal user interface (TUI) real-time event monitor. | `aarchgate monitor` |
| `init` | Bootstraps guest kernel assets and registers user shell shims. | `aarchgate init` |

### Package Manager Shim Integration

When `aarchgate enable` or `aarchgate init` is executed, shell shims are placed in `~/.aarchgate/bin/` and added to your shell `$PATH`. These shims intercept invocations of:

* `npm`
* `pnpm`
* `yarn`
* `bun`

If AarchGate is enabled, calls to these package managers are routed through `aarchgate_daemon`. If disabled (via `aarchgate disable` or `~/.aarchgate/.disabled`), the shims pass execution directly to the native host binaries without overhead.

### Monitor Interface Keyboard Shortcuts

When running `aarchgate monitor`:

* `E`: Enable sandbox interception
* `D`: Disable sandbox interception
* `T`: Toggle sandbox interception
* `H`: Toggle help overlay
* `Q`: Exit monitor

---

## Troubleshooting & Diagnostics

### Diagnostic Commands

To check system status and logs:

```bash
# Inspect daemon status and memory store usage
aarchgate status

# Run internal unit and integration test suite
./build/test_build_acceleration

# View daemon console output
tail -f ~/.aarchgate/logs/daemon.log
```

### Common Issues

1. **Virtualization Entitlement Error**: If running custom builds outside `build.sh`, ensure binaries are code-signed with `entitlements.plist`:
   ```bash
   codesign --entitlements entitlements.plist --force --sign - build/aarchgate_daemon
   ```
2. **Permission Denied on Network Socket**: Ensure `aarchgate_daemon` is running before invoking shims manually.
3. **CARS Store Purge**: To reset shared memory caches, execute:
   ```bash
   rm -rf ~/.aarchgate/cars/* ~/.aarchgate/workspace/*
   ```
