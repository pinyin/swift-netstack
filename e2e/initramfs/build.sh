#!/usr/bin/env bash
# Build the initramfs for SwiftNetStack E2E tests.
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

# Copy busybox and optional extra binaries
mkdir -p "$BUILD_DIR/bin"
cp "$SCRIPT_DIR/bin/busybox" "$BUILD_DIR/bin/busybox"
chmod +x "$BUILD_DIR/bin/busybox"
if [ -f "$SCRIPT_DIR/bin/iperf3" ]; then
    cp "$SCRIPT_DIR/bin/iperf3" "$BUILD_DIR/bin/iperf3"
    chmod +x "$BUILD_DIR/bin/iperf3"
fi

# Create symlinks for busybox applets
BUSYBOX_APPLETS=(
    sh ash cat echo mount umount sleep
    ip ifconfig route ping
    udhcpc nslookup nc
    ls mkdir poweroff
    awk grep head tail sed wc tr cut
    chmod cp ln arp
    wget sha256sum md5sum base64 hexdump
    printf xargs split expr
    dd cmp seq kill
)
for applet in "${BUSYBOX_APPLETS[@]}"; do
    ln -sf busybox "$BUILD_DIR/bin/$applet"
done

# Create essential directories
mkdir -p "$BUILD_DIR"/{etc,proc,sys,dev,dev/pts,dev/shm,run,tmp,var,root,sbin,usr/share/udhcpc,tests}

# Copy init
cp "$SCRIPT_DIR/init" "$BUILD_DIR/init"
chmod +x "$BUILD_DIR/init"

# Copy all test scripts
for f in "$SCRIPT_DIR/tests/"*; do
    cp "$f" "$BUILD_DIR/tests/"
    chmod +x "$BUILD_DIR/tests/$(basename "$f")"
done

# Install udhcpc callback at the path busybox expects
ln -sf /tests/udhcpc.script "$BUILD_DIR/usr/share/udhcpc/default.script"

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
