#!/bin/bash
# AarchGate transparent npm shim — v3.0
# Intercepts `npm install` and routes through the sandbox automatically.
# All other npm commands (run, test, publish, etc.) pass through unchanged.
# Respects `aarchgate disable` / `aarchgate enable` state instantly.

REAL_NPM=$(which -a npm | grep -v "$0" | head -1)
DAEMON_BIN="$(dirname "$0")/../bin/aarchgate_daemon"
AARCHGATE_CLI="$(dirname "$0")/../bin/aarchgate"
KERNEL="$HOME/.aarchgate/vmlinuz.img"
INITRD="$HOME/.aarchgate/initrd.img"
DISABLED_FLAG="$HOME/.aarchgate/.disabled"

# ── Respect enable/disable state ─────────────────────────────────────────────
if [ -f "$DISABLED_FLAG" ]; then
    echo -e "\033[1;33m[AarchGate] ⚠  PROTECTION DISABLED — running unsandboxed\033[0m" >&2
    echo -e "\033[0;33m[AarchGate]    Run 'aarchgate enable' to restore protection.\033[0m" >&2
    exec "$REAL_NPM" "$@"
fi

# ── Only sandbox install/ci commands ─────────────────────────────────────────
case "$1" in
  install|i|ci|add)
    if ! pgrep -q iox-roudi; then
        echo "[AarchGate] Starting IPC bus..." >&2
        /usr/local/bin/iox-roudi > /dev/null 2>&1 &
        sleep 0.5
    fi

    echo -e "\033[0;32m[AarchGate] 🛡  Sandboxed: npm $*\033[0m" >&2
    echo -e "\033[0;34m[AarchGate]    Monitor:  aarchgate monitor\033[0m" >&2
    echo -e "\033[0;34m[AarchGate]    Disable:  aarchgate disable\033[0m" >&2

    "$DAEMON_BIN" \
      --kernel "$KERNEL" \
      --initrd "$INITRD" \
      --share  "$(pwd)"

    EXIT=$?
    if [ $EXIT -eq 0 ]; then
        echo -e "\033[0;32m[AarchGate] ✅ Install clean. No threats detected.\033[0m" >&2
    else
        echo -e "\033[0;31m[AarchGate] 🚨 BLOCKED: Policy violation. node_modules NOT installed.\033[0m" >&2
        echo -e "\033[0;31m[AarchGate]    Run 'aarchgate monitor' to see what was caught.\033[0m" >&2
        exit 1
    fi
    ;;
  *)
    exec "$REAL_NPM" "$@"
    ;;
esac
