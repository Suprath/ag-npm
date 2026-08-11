#!/bin/bash
# AarchGate transparent yarn shim — v3.0

REAL_YARN=$(which -a yarn | grep -v "$0" | head -1)
DAEMON_BIN="$(dirname "$0")/../bin/aarchgate_daemon"
KERNEL="$HOME/.aarchgate/vmlinuz.img"
INITRD="$HOME/.aarchgate/initrd.img"
DISABLED_FLAG="$HOME/.aarchgate/.disabled"

if [ -f "$DISABLED_FLAG" ]; then
    echo -e "\033[1;33m[AarchGate] ⚠  PROTECTION DISABLED — running unsandboxed\033[0m" >&2
    echo -e "\033[0;33m[AarchGate]    Run 'aarchgate enable' to restore protection.\033[0m" >&2
    exec "$REAL_YARN" "$@"
fi

case "$1" in
  ""|install|add)
    if ! pgrep -q iox-roudi; then
        /usr/local/bin/iox-roudi > /dev/null 2>&1 &
        sleep 0.5
    fi

    echo -e "\033[0;32m[AarchGate] 🛡  Sandboxed: yarn $*\033[0m" >&2
    "$DAEMON_BIN" --kernel "$KERNEL" --initrd "$INITRD" --share "$(pwd)"

    EXIT=$?
    if [ $EXIT -eq 0 ]; then
        echo -e "\033[0;32m[AarchGate] ✅ Install clean. No threats detected.\033[0m" >&2
    else
        echo -e "\033[0;31m[AarchGate] 🚨 BLOCKED: Policy violation. node_modules NOT installed.\033[0m" >&2
        exit 1
    fi
    ;;
  *)
    exec "$REAL_YARN" "$@"
    ;;
esac
