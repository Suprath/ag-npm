---
name: aarchgate-npm-sandbox
description: Setup, toggle ON/OFF, and benchmark AarchGate Zero-Trust micro-VM sandbox and build acceleration engine for npm/pnpm/yarn/bun projects on Apple Silicon macOS.
---

# AarchGate Agent Workflow & Benchmark Instructions

This skill provides step-by-step instructions for an AI agent to set up, toggle ON/OFF, and benchmark AarchGate in any npm/pnpm/yarn/bun project on Apple Silicon macOS.

---

## Prerequisite Verification

Before executing setup, verify that the host machine satisfies:
1. macOS Ventura (13.0) or later on Apple Silicon (`ARM64`).
2. Run `uname -m` to confirm `arm64`.

---

## Step 1: Environment & Dependency Setup

Run the single-command dependency installer:

```bash
./scripts/setup_mac_deps.sh
```

Or via Homebrew:
```bash
brew tap Suprath/aarchgate https://github.com/Suprath/ag-npm.git
brew install aarchgate
```

---

## Step 2: Sandbox Initialization & Verification

Execute guest asset bootstrapping and register shell shims:

```bash
aarchgate init
```

Verify status:
```bash
aarchgate status
```

---

## Step 3: Toggling AarchGate ON and OFF for A/B Testing

Use the following commands to toggle protection:

| Goal | Command | Verification |
| :--- | :--- | :--- |
| **Enable Protection (ON)** | `aarchgate enable` | `aarchgate status` displays `Sandbox: ENABLED` |
| **Disable Protection (OFF)** | `aarchgate disable --force` | `aarchgate status` displays `Sandbox: DISABLED` |
| **Toggle Current State** | `aarchgate toggle` | Flips state between `ENABLED` and `DISABLED` |

---

## Step 4: A/B Benchmark Protocol on a Real npm Project

To run an A/B benchmark comparison on a target Node.js project:

### Phase A: Benchmark WITH Protection (AarchGate ENABLED)

```bash
# 1. Ensure AarchGate is enabled
aarchgate enable

# 2. Run clean warm install in project directory
rm -rf node_modules
time npm install --registry https://registry.npmjs.org/

# 3. Test single package incremental addition
time npm install express --registry https://registry.npmjs.org/
```

### Phase B: Benchmark WITHOUT Protection (AarchGate DISABLED)

```bash
# 1. Disable AarchGate
aarchgate disable --force

# 2. Run clean warm install in project directory
rm -rf node_modules
time npm install --registry https://registry.npmjs.org/

# 3. Test single package incremental addition
time npm install express --registry https://registry.npmjs.org/
```

### Phase C: Run Live Engine Micro-Benchmarks

```bash
./build/bench_build_acceleration
```

---

## Step 5: Complete Cleanup & Reset

To restore the system to its original state in one command:

```bash
./cleanup.sh
```
