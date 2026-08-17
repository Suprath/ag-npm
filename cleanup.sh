#!/bin/bash
# (c) 2026 Suprath PS. All rights reserved.
# AarchGate Single-Command Complete Reset & Uninstall Script

echo "[AarchGate] Initiating complete cleanup and uninstall..."

# 1. Stop all running AarchGate processes
echo "[1/5] Stopping all background daemons..."
pkill -9 -f aarchgate_monitor 2>/dev/null || true
pkill -9 -f aarchgate_daemon 2>/dev/null || true
pkill -9 -f iox-roudi 2>/dev/null || true

# 2. Unload Launchctl service if registered
echo "[2/5] Unregistering Launchd service..."
if [ -f "$HOME/Library/LaunchAgents/com.aarchgate.daemon.plist" ]; then
    launchctl unload "$HOME/Library/LaunchAgents/com.aarchgate.daemon.plist" 2>/dev/null || true
    rm -f "$HOME/Library/LaunchAgents/com.aarchgate.daemon.plist"
fi

# 3. Remove shell shims from RC files
echo "[3/5] Cleaning up shell RC environment variables..."
for RC in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile"; do
    if [ -f "$RC" ]; then
        sed -i '' '/# AarchGate Zero-Trust/,+4d' "$RC" 2>/dev/null || true
    fi
done

# 4. Uninstall Homebrew formula if installed
echo "[4/5] Removing Homebrew installation..."
if command -v brew &>/dev/null; then
    brew uninstall aarchgate 2>/dev/null || true
    brew untap Suprath/aarchgate 2>/dev/null || true
fi

# 5. Clean ~/.aarchgate state directory & temporary sockets
echo "[5/5] Purging state directory and temporary IPC sockets..."
rm -rf "$HOME/.aarchgate"
rm -f /tmp/iox1_* 2>/dev/null || true
rm -rf /tmp/aarchgate* 2>/dev/null || true
rm -rf /tmp/ag_bench_* 2>/dev/null || true

echo ""
echo "[AarchGate] ✓ Complete cleanup finished! System is fully restored to original state."
