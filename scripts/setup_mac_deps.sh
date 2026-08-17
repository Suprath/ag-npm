#!/bin/bash
# (c) 2026 Suprath PS. All rights reserved.
# Single-command macOS dependency installer for AarchGate & npm

set -e

echo "[AarchGate] Checking macOS build and runtime dependencies..."

# 1. Ensure Xcode Command Line Tools
if ! xcode-select -p &>/dev/null; then
    echo "[AarchGate] Installing Xcode Command Line Tools..."
    xcode-select --install
fi

# 2. Ensure Homebrew is installed
if ! command -v brew &>/dev/null; then
    echo "[AarchGate] Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    eval "$(/opt/homebrew/bin/brew shellenv 2>/dev/null || /usr/local/bin/brew shellenv 2>/dev/null)"
fi

# 3. Install build & runtime dependencies via Homebrew in one command
echo "[AarchGate] Installing CMake, Ninja, Node.js (npm) via Homebrew..."
brew install cmake ninja node

echo "[AarchGate] ✓ All macOS dependencies installed successfully!"
