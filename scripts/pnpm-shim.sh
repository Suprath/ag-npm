#!/bin/bash
# AarchGate transparent pnpm shim
# Intercepts `pnpm install` / `pnpm add` and routes through the sandbox.

REAL_PNPM=$(which -a pnpm | grep -v "$0" | head -1)
DAEMON=/usr/local/bin/aarchgate_daemon
KERNEL=~/.aarchgate/vmlinuz.img
INITRD=~/.aarchgate/initrd.img

case "$1" in
  install|i|add|import)
    if ! pgrep -q iox-roudi; then
      echo "[AarchGate] Starting sandbox services..." >&2
      /usr/local/bin/iox-roudi > /dev/null 2>&1 &
      sleep 1
    fi

    echo "[AarchGate] 🛡️  Running sandboxed: pnpm $*" >&2
    "$DAEMON" --kernel "$KERNEL" --initrd "$INITRD" --share "$(pwd)"

    EXIT=$?
    if [ $EXIT -eq 0 ]; then
      echo "[AarchGate] ✅ Install complete. No policy violations detected." >&2
    else
      echo "[AarchGate] 🚨 BLOCKED: Policy violation detected." >&2
      exit 1
    fi
    ;;
  *)
    exec "$REAL_PNPM" "$@"
    ;;
esac
