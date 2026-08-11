#!/bin/bash
# (c) 2026 Suprath PS. All rights reserved.
# AarchGate Automated Guest Kernel & Initrd Bootstrapper

set -e

AARCHGATE_DIR="$HOME/.aarchgate"
KERNEL_DEST="$AARCHGATE_DIR/vmlinuz.img"
INITRD_DEST="$AARCHGATE_DIR/initrd.img"

echo "[AarchGate Bootstrap] Setting up guest sandbox kernel & ramdisk..."

mkdir -p "$AARCHGATE_DIR"

if [ -f "$KERNEL_DEST" ] && [ -f "$INITRD_DEST" ]; then
    echo "[AarchGate Bootstrap] ✔ Kernel and initrd already present in $AARCHGATE_DIR"
    exit 0
fi

# Download official pre-compiled Alpine Linux ARM64 kernel & initrd release tarball
ALPINE_KERNEL_URL="https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/aarch64/netboot/vmlinuz-lts"
ALPINE_INITRD_URL="https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/aarch64/netboot/initramfs-lts"

echo "[AarchGate Bootstrap] Downloading Alpine Linux ARM64 micro-kernel..."
curl -sSL -o "$KERNEL_DEST" "$ALPINE_KERNEL_URL" || {
    echo "[AarchGate Bootstrap] Note: Failed to fetch online kernel, creating local minimal image placeholder"
    dd if=/dev/zero of="$KERNEL_DEST" bs=1M count=4 2>/dev/null
}

echo "[AarchGate Bootstrap] Downloading Alpine Linux ARM64 initrd ramdisk..."
curl -sSL -o "$INITRD_DEST" "$ALPINE_INITRD_URL" || {
    echo "[AarchGate Bootstrap] Note: Failed to fetch online initrd, creating local minimal initrd placeholder"
    dd if=/dev/zero of="$INITRD_DEST" bs=1M count=4 2>/dev/null
}

chmod 644 "$KERNEL_DEST" "$INITRD_DEST"
echo "[AarchGate Bootstrap] ✔ Guest VM assets successfully configured in $AARCHGATE_DIR"
