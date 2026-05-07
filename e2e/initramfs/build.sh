#!/usr/bin/env bash
# Build the initramfs for SwiftNetStack DHCP E2E tests.
#
# Requires:
#   - busybox (aarch64 static) at initramfs/bin/busybox
#   - cpio, gzip
#
# Output: initramfs/initramfs.cpio.gz

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$(mktemp -d /tmp/swiftnetstack-initramfs.XXXXXX)"
trap 'rm -rf "$BUILD_DIR"' EXIT

echo "Building initramfs in $BUILD_DIR..."

# Copy busybox
mkdir -p "$BUILD_DIR/bin"
cp "$SCRIPT_DIR/bin/busybox" "$BUILD_DIR/bin/busybox"
chmod +x "$BUILD_DIR/bin/busybox"

# Create symlinks for busybox applets used by our init script
BUSYBOX_APPLETS=(
    sh ash cat echo mount umount sleep
    ip ifconfig route ping
    udhcpc ls mkdir poweroff
    awk grep head tail
    chmod cp ln
)
for applet in "${BUSYBOX_APPLETS[@]}"; do
    ln -sf busybox "$BUILD_DIR/bin/$applet"
done

# Create essential directories
mkdir -p "$BUILD_DIR"/{etc,proc,sys,dev,dev/pts,dev/shm,run,tmp,var,root,sbin,usr/share/udhcpc}

# Copy init and udhcpc script
cp "$SCRIPT_DIR/init" "$BUILD_DIR/init"
chmod +x "$BUILD_DIR/init"
cp "$SCRIPT_DIR/udhcpc.script" "$BUILD_DIR/usr/share/udhcpc/default.script"
chmod +x "$BUILD_DIR/usr/share/udhcpc/default.script"

# Create /etc/inittab (minimal)
cat > "$BUILD_DIR/etc/inittab" <<'EOF'
::sysinit:/etc/init.d/rcS
::askfirst:-/bin/sh
EOF

# Create /etc/group and /etc/passwd (minimal)
echo "root:x:0:" > "$BUILD_DIR/etc/group"
echo "root:x:0:0:root:/root:/bin/sh" > "$BUILD_DIR/etc/passwd"

# Pack as cpio.gz
OUTPUT="$SCRIPT_DIR/initramfs.cpio.gz"
echo "Packing $OUTPUT..."
(cd "$BUILD_DIR" && find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "$OUTPUT")
ls -lh "$OUTPUT"
echo "Done."
