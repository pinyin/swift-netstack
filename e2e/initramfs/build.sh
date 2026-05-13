#!/usr/bin/env bash
# Build the SwiftNetStack E2E bootc-based initramfs.
#
# Runs on the local Fedora server (x86_64), cross-compiles for aarch64.
#
# Usage:
#   ./build.sh
#
# Prerequisites (on the server):
#   - podman + qemu-user-static (for aarch64 emulation)
#   - cpio, gzip
#
# Output:
#   output/initramfs.cpio.gz    # Fedora rootfs as initramfs

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"
IMAGE_NAME="swift-netstack-e2e"

mkdir -p "$OUTPUT_DIR"

# ── Step 1: Build bootc OCI image (aarch64 cross-compile on x86_64) ─

echo "=== Step 1: Building bootc container (linux/arm64) ==="
podman build \
    --platform linux/arm64 \
    -t "${IMAGE_NAME}:latest" \
    "$SCRIPT_DIR"
echo "Container built: ${IMAGE_NAME}:latest"

# ── Step 2: Export rootfs → initramfs cpio.gz ──────────────────────

echo ""
echo "=== Step 2: Exporting rootfs for initramfs ==="

TEMP_DIR="$(mktemp -d /tmp/bootc-initramfs.XXXXXX)"
cleanup() { chmod -R u+w "$TEMP_DIR" 2>/dev/null || true; rm -rf "$TEMP_DIR"; }
trap cleanup EXIT

CONTAINER_ID=$(podman create --platform linux/arm64 "${IMAGE_NAME}:latest")
podman export "$CONTAINER_ID" | tar -C "$TEMP_DIR" -xf -
podman rm "$CONTAINER_ID" >/dev/null

# Overlay custom /init (replaces systemd PID 1)
cp "$SCRIPT_DIR/init" "$TEMP_DIR/init"
chmod +x "$TEMP_DIR/init"

INITRD="$OUTPUT_DIR/initramfs.cpio.gz"
echo "Packaging $INITRD ..."
(cd "$TEMP_DIR" && find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "$INITRD")
ls -lh "$INITRD"

echo ""
echo "=== Done ==="
echo "Initramfs: $INITRD"
echo ""
echo "Run e2e test with:"
echo "  cd $(dirname "$SCRIPT_DIR") && ./run.sh"
